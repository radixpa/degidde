
from .models import User, ExternalUser, Permission
from .utils import ExpireDict


# In process cache, with 1 day expiration
_group_perms_cache = ExpireDict(86400)         # 24 * 60 * 60


class ModelBackend(object):
    user_cls = User

    def authenticate(self, username, password):
        '''
        Here username can also be the user's email address.
        '''
        if u'@' in username:
            u = self.user_cls.fetch_by_email(username)
            if u and not u.is_validated:
                u = None
        else:
            u = User.fetch(username)
        if u and u.check_password(password):
            return u

    def get_user(self, user_id):
        return self.user_cls.fetch(user_id)

    def get_group_permissions(self, user_obj):
        group = user_obj.group
        if group not in _group_perms_cache:
            # This must be as idempotent as possible!
            perms = frozenset(p.perm for p in Permission.fetch_by_group(user_obj.group))
            _group_perms_cache[group] = perms
        return _group_perms_cache[group]

    def has_perm(self, user_obj, perm):
        # Faster for users that have the permission.
        # This is not enough for checking persmissions,
        # ensuring the connexion is secure and, that
        # the user has logged in with a password, is
        # also required. Use a decorator for this.

        r = perm in self.get_group_permissions(user_obj)
        if r:
            return True
        if not hasattr(user_obj, '_perm_cache'):
            user_obj._perm_cache = set()
        if perm in user_obj._perm_cache:
            return True
        if Permission.fetch(user_obj.username, perm):
            user_obj._perm_cache.add(perm)
            return True
        return False


class ExternalUserBackend(ModelBackend):
    user_cls = ExternalUser

    def authenticate(self, service):
        return self.user_cls.fetch(service=service) 

