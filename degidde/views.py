from django.http import HttpResponse, HttpResponseNotAllowed

from .utils import Encoder


def form_post(request, form, **kwargs):
    if request.method != "POST":
        return HttpResponseNotAllowed(['POST'])
    authenticate
    
    f = form(request.POST, **kwargs)


def model(request, getter, params=(), **kwargs):
    if request.method != "GET":
        return HttpResponseNotAllowed(['GET'])
    kwargs.update({k:request.GET[k] for k in params if k in request.GET})
    m = getter(**kwargs)
    return HttpResponse(Encoder.encode(m))


form = form_post
