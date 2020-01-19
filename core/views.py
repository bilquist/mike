# core/views.py

from django.shortcuts import render
from django.views.generic.base import View
from django.urls import reverse_lazy




class HomePageView(View):
	template_name = 'core/home.html'
	
	def get(self, request, *args, **kwargs):
		return render(request, self.template_name)
