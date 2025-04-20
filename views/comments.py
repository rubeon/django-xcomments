from django.core import validators

from django import forms

from django.core.mail import mail_admins, mail_managers
from django.http import Http404
from django.core.exceptions import ObjectDoesNotExist
# from django.shortcuts import render_to_response
from django.template import RequestContext
from xcomments.models import Comment, FreeComment, RATINGS_REQUIRED, RATINGS_OPTIONAL, IS_PUBLIC
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.forms import AuthenticationForm
from django.http import HttpResponseRedirect, HttpResponse
from django.utils.text import normalize_newlines
from django.conf import settings
from django.utils.translation import ngettext
from xblog.external.akismet import Akismet 
from django.contrib.sites.models import Site
from django.utils.translation import gettext as _

import base64, datetime
import logging
LOGGER=logging.getLogger(__name__)
COMMENTS_PER_PAGE = 20
LOGGER.debug("IMPORTING xcomments.views.comments")


def post_comment(request):
    """
    Post a comment

    Redirects to the `comments.comments.comment_was_posted` view upon success.

    Templates: `comment_preview`
    Context:
        comment
            the comment being posted
        comment_form
            the comment form
        options
            comment options
        target
            comment target
        hash
            security hash (must be included in a posted form to succesfully
            post a comment).
        rating_options
            comment ratings options
        ratings_optional
            are ratings optional?
        ratings_required
            are ratings required?
        rating_range
            range of ratings
        rating_choices
            choice of ratings
    """
    if not request.POST:
        raise Http404(_("Only POSTs are allowed"))
    try:
        options, target, security_hash = request.POST['options'], request.POST['target'], request.POST['gonzo']
    except KeyError:
        raise Http404(_("One or more of the required fields wasn't submitted"))
    photo_options = request.POST.get('photo_options', '')
    rating_options = normalize_newlines(request.POST.get('rating_options', ''))
    if Comment.objects.get_security_hash(options, photo_options, rating_options, target) != security_hash:
        raise Http404(_("Somebody tampered with the comment form (security violation)"))
    # Now we can be assured the data is valid.
    if rating_options:
        rating_range, rating_choices = Comment.objects.get_rating_options(base64.decodestring(rating_options))
    else:
        rating_range, rating_choices = [], []
    content_type_id, object_id = target.split(':') # target is something like '52:5157'
    try:
        obj = ContentType.objects.get(pk=content_type_id).get_object_for_this_type(pk=object_id)
    except ObjectDoesNotExist:
        raise Http404(_("The comment form had an invalid 'target' parameter -- the object ID was invalid"))
    option_list = options.split(',') # options is something like 'pa,ra'
    new_data = request.POST.copy()
    new_data['content_type_id'] = content_type_id
    new_data['object_id'] = object_id
    new_data['ip_address'] = request.META.get('REMOTE_ADDR')
    new_data['is_public'] = IS_PUBLIC in option_list
    # If user gave correct username/password and wasn't already logged in, log them in
    # so they don't have to enter a username/password again.

class PublicFreeCommentForm(forms.Form):
    person_name = forms.CharField(label="Your Name")
    person_url = forms.CharField(label="Web Site", required=False)
    person_email = forms.EmailField(label="Email Address")
    comment = forms.CharField(widget=forms.Textarea(attrs={'rows':10, 'cols':50}, ) )
    options = forms.CharField(widget=forms.HiddenInput)
    target = forms.CharField(widget=forms.HiddenInput)
    gonzo = forms.CharField(widget=forms.HiddenInput)

def post_free_comment(request):
    """
    Post a free comment (not requiring a log in)

    Redirects to `comments.comments.comment_was_posted` view on success.

    Templates: `comment_free_preview`
    Context:
        comment
            comment being posted
        comment_form
            comment form object
        options
            comment options
        target
            comment target
        hash
            security hash (must be included in a posted form to succesfully
            post a comment).
    """
    LOGGER.debug( "post_free_comment called")
    if not request.POST:
        raise Http404(_("Only POSTs are allowed"))
    try:
        options, target, security_hash = request.POST['options'], request.POST['target'], request.POST['gonzo']
    except KeyError:
        raise Http404(_("One or more of the required fields wasn't submitted"))
    if Comment.objects.get_security_hash(options, '', '', target) != security_hash:
        raise Http404(_("Somebody tampered with the comment form (security violation)"))
    content_type_id, object_id = target.split(':') # target is something like '52:5157'
    content_type = ContentType.objects.get(pk=content_type_id)
    try:
        obj = content_type.get_object_for_this_type(pk=object_id)
    except ObjectDoesNotExist:
        raise Http404( _("The comment form had an invalid 'target' parameter -- the object ID was invalid"))
    option_list = options.split(',')
    new_data = request.POST.copy()
    # print "NEWDATA", new_data
    newform = PublicFreeCommentForm(new_data)

    # print "NEWFORM: ", newform

    new_data['content_type_id'] = content_type_id
    new_data['object_id'] = object_id
    new_data['ip_address'] = request.META['REMOTE_ADDR']
    # new_data['is_public'] = IS_PUBLIC in option_list
    ak_api = Akismet(key=settings.AKISMET_API_KEY, blog_url='http://%s/' % Site.objects.get(pk=settings.SITE_ID).domain)
    LOGGER.debug( "CHECKING AKISMET")
    if ak_api.verify_key():
        ak_data = {
            'user_ip': request.META.get('REMOTE_ADDR', '127.0.0.1'),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'referrer': request.META.get('HTTP_REFERER', ''),
            'comment_type': 'comment',
            'comment_author': new_data.get('person_name', ''),
            }
        # print "AK_DATA:", ak_data
        try:
          res = ak_api.comment_check(new_data.get('comment', ''), data=ak_data, build_data=True)
        except:
          res = True
        
        if res:
            new_data['is_public'] = False
        else:
            new_data['is_public'] = IS_PUBLIC in option_list
    del(ak_api)            

def comment_was_posted(request):
    """
    Display "comment was posted" success page

    Templates: `comment_posted`
    Context:
        object
            The object the comment was posted on
    """
    obj = None
    if request.GET.has_key('c'):
        content_type_id, object_id = request.GET['c'].split(':')
        try:
            content_type = ContentType.objects.get(pk=content_type_id)
            obj = content_type.get_object_for_this_type(pk=object_id)
        except ObjectDoesNotExist:
            pass
    return HttpResponse('xcomments/posted.html', {'object': obj}, context_instance=RequestContext(request))
