from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.index),
    path('show_sign_in', views.show_sign_in),
    path('show_create_account', views.show_create_account),
    path('show_add_new', views.show_add_new),
    path('add_new', views.add_new),
    path('create_user', views.create_user), 
    path('user_login', views.user_login),
    path('logout', views.logout),
    path('show_user/<int:user_id>', views.show_user),
    path('show_user_info/<int:user_id>', views.show_user_info), 
    path('leave_message', views.leave_message),
    path('leave_comment', views.leave_comment),
    path('edit/<int:user_id>', views.show_edit_page),
    path('edit_user_info/<int:user_id>', views.edit_user_info),
    path('edit_user_password/<int:user_id>', views.edit_user_password),
    path('delete/<int:user_id>', views.delete)
]


