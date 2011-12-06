import re
import urlparse

from django import forms
from django.conf import settings
from django.contrib.auth import forms as auth, login, REDIRECT_FIELD_NAME, SESSION_KEY
from django.core import validators
from django.http import HttpResponseRedirect, QueryDict
from django.utils.translation import ugettext_lazy as _

from .models import User, UsernameTakenError
from .utils import same_origin_redirect, FUTURE_DATETIME
from .services import service_session


# Very basic account management forms


USERNAME_MAX_LENGTH = 30
FULL_NAME_MAX_LENGTH = 60


auth.UserCreationForm.password1.min_length = 6
del auth.UserCreationForm.Meta # For now, this is not supported


class UserCreationForm(auth.UserCreationForm):
    username = forms.RegexField(label=_("Username"), max_length=USERNAME_MAX_LENGTH, regex=r'^[\w]+$',
        help_text = _("30 characters or fewer. Letters, digits and _ only."),
        error_messages = {'invalid': _("Only letters, numbers and _.")})
    email = forms.EmailField(label=_("Email"))
    # Better not to displaay this
    full_name = forms.CharField(label=_("Full Name"), max_length=FULL_NAME_MAX_LENGTH, 
                                help_text = _("Optional"))
    # TODO: accept terms and conditions (?)
 
    def __init__(self, request, *args, **kwargs):
        super(UserCreationForm, self).__init__(*args, **kwargs)
        self.login = kwargs.get('login', True)
        self.request = request
        self.fields.keyOrder = ['username', 'email', 'password1', 'password2']

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.fetch(username):
            raise forms.ValidationError(_("This username is already taken."))
        return username

    def clean_email(self):
        email = self.cleaned_data['email'].lower()
        
        if User.fetch_by_email(email):
            raise forms.ValidationError(_("This email is already registered."))
                                          #"Want to login or recover your password?")) # Add this with javascript
        return email

    def clean(self):
        username = self.cleaned_data['username']
        kwargs = {}
        if not username.islower():
            kwargs['csusername'] = username
            username = username.lower()
        user = User(
            username=username,
            email=self.cleaned_data['email']
            full_name=self.cleaned_data.get('full_name')
            **kwargs)
        user.set_password(self.cleaned_data['password1'])
        self.user = user
        return self.cleaned_data

    def save(self, commit=True):
        if commit:
            if self.login:
                self.login(self.user)
            else:
                self.user.save(force_insert=True)
        return self.user

    def login(self, user):
        from .auth_backends import ModelBackend as backend
        # Make sure next time user is saved it is inserted.
        def save(force_insert=True, _old_save=user.save):
            saved = user.save(force_insert=force_insert)
            if not saved:
                raise UsernameTakenError #Very unlikely
            user.save = _old_save
            return user

        user.save = save
        user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)
        login(self.request, user)


class UserConfirmationForm(UserCreationForm):
    password1 = None # TODO: Will this eliminate the fields?
    password2 = None

    # TODO: handle case in which email is already registered,
    # by asking the user if wants to be sent a confirmation email.
    # A new user will not be created in this case. And the rest
    # of the data from this form will be dicarded. User must be
    # made aware of the existence of an old account, to which she
    # is being granted access (similar to the case of email services).

    def clean(self):
        ext = self.request.user
        if not ext.is_external():
            raise forms.ValidationError(_("Your information has already been confirmed."))
        data = super(UserConfirmationForm, self).clean()
        if ext.is_validated:
            self.user.validate()
        self.user.aliased_to = ext.id
        return data

    # TODO: initial data
    def login(self, user):
        # make sure service data is not lost
        session = self.request.session
        data = service_session(session)
        super(UserConfirmationForm, self).login(self.user)
        session.update(data)
    

class AuthenticationForm(forms.Form):
    username = forms.CharField(label=_("Username"), max_length=USERNAME_MAX_LENGTH,
                               help_text=_("Or email, if your account has been validated")) # or email if account has been validated
    password = forms.CharField(label=_("Password"), widget=forms.PasswordInput)
    rememberme = forms.BooleanField(label=_("Remember me"), required=False, initial=True)

    def __init__(self, request, *args, **kwargs):
        self.next_page = kwargs.pop('next_page', None)
        self.redirect_field_name = kwargs.pop('redirect_field_name', REDIRECT_FIELD_NAME)
        self.return_sid = kwargs.pop('return_sid', False)
        self.request = request
        super(AuthenticationForm, self).__init__(*args, **kwargs)

    def clean(self):
        username = self.cleaned_data['username'].lower()
        password = self.cleaned_data['password']
        self.user = authenticate(username=username, password=password)
        if self.user is None:
            raise forms.ValidationError(_("Please enter a correct username and password."))
        elif not self.user_cache.is_active:
            raise forms.ValidationError(_("This account is inactive."))
        self.check_for_test_cookie()
        return self.cleaned_data

    def check_for_test_cookie(self):
        if self.request and not self.request.session.test_cookie_worked():
            raise forms.ValidationError(
                _("Your Web browser doesn't appear to have cookies enabled. "
                  "Cookies are required for logging in."))

    def save(self, commit=True):
        if commit:
            self.login(self.user)
            if self.cleaned_data.get('rememberme', False):
                self.request.session.set_expiry(FUTURE_DATETIME)
        return self.user

    def login(self, user):
        login(self.request, user)
    
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


 
