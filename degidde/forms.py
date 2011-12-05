import re
import urlparse

from django import forms
from django.conf import settings
from django.contrib.auth import forms as auth, login, REDIRECT_FIELD_NAME, SESSION_KEY
from django.http import HttpResponseRedirect, QueryDict
from django.utils.translation import ugettext_lazy as _

from .models import User
from .utils import same_origin_redirect


# Very basic account management forms


auth.UserCreationForm.password1.min_length = 6
del auth.UserCreationForm.Meta # For now, this is not supported


class UserCreationForm(auth.UserCreationForm):
    username = forms.RegexField(label=_("Username"), max_length=30, regex=r'^[\w]+$',
        help_text = _("30 characters or fewer. Letters, digits and _ only."),
        error_messages = {'invalid': _("This value may contain only letters, numbers and _.")})
    email = forms.EmailField(label=_("Email"))
    # TODO: accept terms and conditions (?)
    
    def __init__(self, request, *args, **kwargs):
        super(UserCreationForm, self).__init__(*args, **kwargs)
        self.login = kwargs.get('login', False)
        self.request = request
        self.fields.keyOrder = ['username', 'email', 'password1', 'password2']

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.fetch(username):
            raise forms.ValidationError(_("This username is already taken."))
        return username

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.fetch_by_email(email):
            raise forms.ValidationError(_("This email is already registered."
                                          "Want to login or recover your password?")) #urlize with javascript
        return email

    def save(self, commit=True):
        user = User(
            username = self.cleaned_data['username'],
            email = self.cleaned_data['email'])
        user.set_password(self.cleaned_data['password1'])
        if commit:
            # User will be saved after login, make force_insert be True
            def save(x):
                saved = user.save(force_insert=True) 
                if not saved:
                    raise RuntimeError #Very unlikely

            user.save = save
            if self.login:
                self.login(user)
        return user

    def login(self, user):
        from .auth_backends import ModelBackend as backend
        
        user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)
        login(self.request, user)


class UserConfirmationForm(UserCreationForm):
    
    

class AuthenticationForm(auth.AuthenticationForm):
    rememberme = forms.BooleanField(required=False, initial=True)

    def __init__(self, *args, **kwargs):
        self.next_page = kwargs.pop('next_page', None)
        self.redirect_field_name = kwargs.pop('redirect_field_name', REDIRECT_FIELD_NAME)
        self.return_sid = kwargs.pop('return_sid', False)
        super(AuthenticationForm, self).__init__(*args, **kwargs)
        #self.origin = (self.request.is_secure() and "https://" or "http://") + self.request.get_host()

    def save(self, commit=True):
        user = self.get_user()
        login(self.request, user)
        return user
    
    def get_result(self): #recosider
        session = self.request.session
        if session.test_cookie_worked():
            session.delete_test_cookie()
        response = same_origin_redirect(self.request, self.request.GET.get(self.redirect_field_name))
        if response:
            return response
        sid = session[SESSION_KEY]
        if next_page:
            if self.return_sid:
                next_page_parts = list(urlparse.urlparse(next_page))
                querystring = QueryDict(next_page_parts[4], mutable=True)
                querystring["sid"] = sid # hard coded!
                next_page_parts[4] = querystring.urlencode(safe='/')
                next_page = urlparse.urlunparse(next_page_parts)
            return HttpResponseRedirect(next_page)
        if self.return_sid:
            return sid


#class PasswordResetForm
#...



class         


 
