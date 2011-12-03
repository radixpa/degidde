from google.appengine.ext import db

from degidde.models import *


def _insert(obj, id):
    def txn():
        if not obj.fetch(id):
            obj.put()
            return obj

    if self.is_saved():
        return
    if self._session_key:
        return db.run_in_transaction(txn)


def dump(obj,):
    key_name = None
    try:
        kind = obj.kind()
        key_name = obj.name()
    except AttributeError:
        pass
    if key_name is None:
        raise TypeError("db.Key instance with a name is required")
    cls = db.class_for_kind(kind)
    try:
        return cls.parse_key_name(key_name)
    except AttributeError:
        return key_name


class Session(db.Model):
    session_data = db.BlobProperty(required=True)
    expire_date = db.DateTimeProperty(required=True, indexed=False)

    def __init__(self, *args, **kwargs):
        key = kwargs.pop('session_key', None)
        if key:
            super(Session, self).__init__(key_name=key, *args, **kwargs)
        else:
            super(Session, self).__init__(*args, **kwargs)
        self._session_key = key

    @property
    def session_key(self):
        if self.is_saved():
            return self.key().name()
        return self._session_key

    @classmethod
    def fetch(cls, session_key): #, expires_after=None):
        obj = cls.get_by_key_name(session_key)
        #if expires_after:
        #    return expires_after < obj.expire_date and obj or None
        return obj

    @classmethod
    def remove(cls, session_key):
        db.delete(db.Key.from_path(cls.kind(), session_key))

    def save(self, force_insert=False):
        if force_insert and self._session_key:
            return _insert(self, self._session_key)
        self.put()
        return self


class Permission(db.Model):
    # This properties will all be cached!
    granted_by = db.StringProperty(required=True)
    date_granted = db.DateTimeProperty(auto_now_add=True)
    #expires = db.DateTime...

    _group_pre = u'@'
    _perm_pre = u'/'

    def __init__(self, *args, **kwargs):
        # group must be one of the predefined groups in settings,
        # same applies to perm.

        perm = kwargs.pop('perm', None)
        if perm:
            username = kwargs.pop('username', None)
            group = kwargs.pop('group', None)
            validate_permission(username, group, perm)
            key = self._make_key_name(username, group, perm)
            self.username = username
            self.group = group
            self.perm = perm
            super(Permission, self).__init__(key_name = key, *args, **kwargs)
        else:
            super(Permission, self).__init__(*args, **kwargs)
            self.username, self.group, self.perm = self.parse_key_name()

    @classmethod
    def _make_key_name(cls, username, group, perm):
        if group:
            start = cls._group_pre + group
        else:
            start = username # There must be a username
        return start + cls._perm_pre + (perm or '')
    
    @classmethod
    def parse_key_name(cls, key_name):
        start, perm = key_name.split(self._perm_pre, 1)
        username = group = None
        if start.startswith(cls._group_pre):
            group = start[1:]
        else:
            username = start
        return username, group, perm or None
 
    _cache_key = lambda cls, group, perm: not perm and group
    @cache(_cache_key, namespace='Permission')
    def fetch_by_group(cls, group, perm=None):
        return cls.fetch(None, perm, _group=group)

    save = fetch_by_group.invalidate(lambda self: self.group)(db.Model.put)

    @fetch_by_group.invalidate(_cache_key)
    def remove_by_group(cls, group, perm=None):
        return cls.remove(None, perm, _group=group)

    fetch_by_group = classmethod(fetch_by_group)
    remove_by_group = classmethod(remove_by_group)

    def remove(cls, username, perm=None, _group=None):
        if not (username or _group):
            return
        key = cls._make_key_name(username, _group, perm)
        if perm:
            db.delete(db.Key(cls.kind(), key))
        else:
            db.delete(list(cls.all(keys_only=True).filter(
                '__key__ >', db.Key.from_path(cls.kind(), key)
            ).filter(
                '__key__ <', db.Key.from_path(cls.kind(), key + u'\ufffd')
            )))
        
    @classmethod
    def fetch(cls, username, perm=None, _group=None):
        if not (username or _group):
            return ()
        key = cls._make_key_name(username, _group, perm)
        if perm:
            return cls.get_by_key_name(key)
        else:
            return cls.all().filter(
                '__key__ >', db.Key.from_path(cls.kind(), key)
            ).filter(
                '__key__ <', db.Key.from_path(cls.kind(), key + u'\ufffd')
            )


class User(db.Model, UserBase):
    full_name = db.StringProperty()
    email = db.EmailProperty(required=True)
    password = db.StringProperty(default=UNUSABLE_PASSWORD, indexed=False)
    group = db.StringProperty()
    is_active = db.BooleanProperty(default=True)
    date_validated = db.DateTimeProperty(default=FUTURE_DATETIME)
    last_login = db.DateTimeProperty(auto_now_add=True)
    date_joined = db.DateTimeProperty(auto_now_add=True)
    aliased_to = db.StringProperty()

    def __init__(self, *args, **kwargs):
        key = kwargs.pop('username', None)
        if key:
            super(User, self).__init__(key_name=key, *args, **kwargs)
        else:
            super(User, self).__init__(*args, **kwargs)
        self._username = key

    @property
    def username(self):
        if self.is_saved():
            return self.key().name() #Assumes that a key will always have a name
        return self._username

    def fetch(cls, username):
        return cls.get_by_key_name(username)

    def remove(cls, username):
        db.delete(db.Key.from_path(cls.kind(), username))
    
    def save(self, force_insert=False):
        if force_insert and self._username:
            return _insert(self, self._username)
        self.put()
        return self

    if USER_CACHE_TIMEOUT:
        _cache_key = lambda cls, username: username
        fetch = cache(_cache_key, timeout=USER_CACHE_TIMEOUT, namespace='User')(fetch)
        save = fetch.invalidate(lambda self: self.username)(save)
        remove = fetch.invalidate(_cache_key)(remove)
    fetch = classmethod(fetch)
    remove = classmethod(remove)
 
    @classmethod
    def fetch_by_email(cls, email, first=True):
        query = cls.all().filter('email', email).order('date_validated')
        if first:
            return query.get()
        return query #reconsider!

    @classmethod
    def fetch_by_alias(cls, alias):
        obj = cls.all().filter('aliased_to', alias).get()
        if obj:
            return obj

        alias = UserAlias.get_by_key_name(alias)
        if alias:
            return cls.fetch(alias.username)

    def save_alias(self, alias):
        UserAlias(key_name=alias, username=self.username).put()

    def remove_alias(self, alias):
        db.delete(db.Key(UserAlias.kind(), alias))

    def list_aliases(self):
        return [k.name() for k 
                in UserAlias.all(keys_only=True).filter('username', self.username)]


# TODO: Add ratelimiting and/or recaptcha
# There should be a way for users to provide a username after they do external login


class UserAlias(db.Model):
    username = db.StringProperty(required=True)
    # this will only work when using the ModelBackend
    # TODO: this should allow users to change their username
    
    #def __init__(self, *args, **kwargs):
    #    key = kwargs.pop('alias')
    #    if key:
    #        super(UserAlias, self).__init__(key_name=key, *args, **kwargs)
    #    else:
    #        super(UserAlias, self).__init__(*args, **kwargs)
    #    self._alias = key
        
    #@property
    #def alias(self):
    #    if self.is_saved():
    #        return self.key().name()
    #    return self._alias

    #@classmethod
    #def fetch(cls, alias):
    #    return cls.get_by_key_name(alias)

    #@classmethod
    #def remove(cls, alias):
    #    db.delete(db.Key.from_path(cls.kind(), alias))

    #def save(self, force_insert=False):
    #    if force_insert and self._alias:
    #        return _insert(self, self._alias)
    #    self.put()
    #    return self
