from .models import User, ExternalUser, Permission


_group_permissions_cache = {}


class ModelBackend(object):
    user_cls = User

    def authenticate(self, username, password):
        '''
        Here username can also be the user's email address.
        '''
        if '@' in username:
            u = self.user_cls.fetch_by_email(username)
            if not u.is_validated:
                u = None
        else:
            u = User.fetch(username)
        if u and u.check_password(password):
            return u

    def get_user(self, user_id):
        return self.user_cls.fetch(user_id)

    def get_group_permissions(self, user_obj):
        group = user_obj.group
        if group not in _group_permissions_cache:
            # This must be as idempotent as possible!
            perms = frozenset(p.perm for p in Permission.fetch_by_group(user_obj.group))
            _group_permissions_cache[group] = perms
        return _group_permissions_cache[group]

    def has_perm(self, user_obj, perm):
        r = perm in self.get_group_permissions(user_obj)
        if r:
            return r
        return bool(Permission.fetch(user_obj.username, perm))


class ExternalUserBackend(ModelBackend):
    user_cls = ExternalUser

    def authenticate(self, service):
        return self.user_cls.fetch(service=service) 

