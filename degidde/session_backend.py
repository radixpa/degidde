import datetime

from django.contrib.sessions.backends.base import SessionBase, CreateError
from django.contrib.sessions.backends.cached_db import SessionStore as CacheStore
from django.core.exceptions import SuspiciousOperation
from django.utils.encoding import force_unicode

from .models import Session
from .utils import as_base_of


@as_base_of(CacheStore)
class SessionStore(SessionBase):
    def load(self):
        s = Session.fetch(self.session_key) 
        if s and datetime.datetime.now() < s.expire_date:
            try:
                return self.decode(force_unicode(s.session_data))
            except SuspiciousOperation:
                # TODO: this looks like the place to throttle
                # against an attempt trying to guess a valid session cookie
                pass
        self.create()
        return {}

    def exists(self, session_key):
        return bool(Session.fetch(session_key))

    def create(self):
        while True:
            self.session_key = self._get_new_session_key()
            try:
                self.save(must_create=True)
            except CreateError:
                continue
            self.modified = True
            self._session_cache = {}
            return

    def save(self, must_create=False):
        obj = Session(
            session_key=self.session_key,
            session_data=self.encode(self._get_session(no_load=must_create)),
            expire_date=self.get_expiry_date()
        )
        saved = obj.save(force_insert=must_create)
        if not saved:
            raise CreateError

    def delete(self, session_key=None):
        if session_key is None:
            if self._session_key is None:
                return
            session_key = self._session_key
        Session.remove(session_key)

