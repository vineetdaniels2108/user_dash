from django import http
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from .models import *
import bcrypt

# Create your views here.

def index(request):
    
    context = {
        'all_users' : User.objects.all()
    }
    return render (request, 'home_v1.html', context)
    
def show_sign_in(request):
    return render (request, 'sign_in.html')

def show_create_account(request):
    return render (request, 'create_account.html')

def show_add_new(request):
    logged_user = User.objects.get(id = request.session['user'])
    context = {
        'user': logged_user
    }
    return render (request, 'add_new.html',context)

def create_user (request): 
    if request.method == 'POST':    
        errors = User.objects.RegistrationValidator(request.POST)
        if len(errors) >0: 
            for k,v in errors.items():
                messages.error(request, v)
                
            return redirect('/')
        
        else: 
            hashedpw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode()
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            email = request.POST['email']
            description = 'Adding a new user'
            all_users = User.objects.all()
            if len(all_users)==0:
                user_level = 'admin'
            else:
                user_level = 'normal'
            
            new_user = User.objects.create(first_name = first_name, last_name = last_name, email = email, password = hashedpw, user_level = user_level, description = description)
            
            new_user_id = new_user.id
            
            request.session['user'] = new_user_id
            
            context = {
                'log_user' : new_user,
                'all_users' : all_users
            }
            
            return redirect (f'/show_user/{new_user_id}')
    
    else:
        return redirect ( '/')
    
def add_new (request): 
    if request.method == 'POST':    
        errors = User.objects.RegistrationValidator(request.POST)
        if len(errors) >0: 
            for k,v in errors.items():
                messages.error(request, v)
                
            return redirect('/show_add_new')
        
        else: 
            logged_user = User.objects.get(id = request.session['user'])
            hashedpw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode()
            first_name = request.POST['first_name']
            last_name = request.POST['last_name']
            email = request.POST['email']
            description = 'Adding a new user'
            all_users = User.objects.all()
            if len(all_users)==0:
                user_level = 'admin'
            else:
                user_level = 'normal'
            new_user = User.objects.create(first_name = first_name, last_name = last_name, email = email, password = hashedpw, user_level = user_level, description = description)
            request.session['user'] = logged_user.id
            logged_user_id = logged_user.id
            
            return redirect (f'/show_user/{logged_user_id}')
    
    else:
        return redirect ( '/show_add_new')
    
def user_login(request): 
    if request.method == 'POST':
        errors = User.objects.LoginValidator(request.POST)
        if len(errors) >0: 
            for k,v in errors.items():
                messages.error(request, v)
                
            return redirect ('/')
        
        else:
            user_log = User.objects.get(email = request.POST['email'])
            request.session['user'] = user_log.id
            user_id = user_log.id
            return redirect (f'/show_user/{user_id}')
        
    else:
        return redirect('/')
    
def show_user(request, user_id):
    logged_user = User.objects.get(id = user_id)
    context = {
                'log_user' : logged_user,
                'all_users' : User.objects.all()
            }
    
    return render (request, 'user.html', context)

def show_user_info(request, user_id):
    logged_user = User.objects.get(id = request.session['user'])
    info_user = User.objects.get(id = user_id)
    all_messages = info_user.posted_for.all()
    
    context = {
        'log_user': logged_user,
        'user': info_user,
        'all_messages': all_messages
    }
    
    return render (request, 'user_info.html', context)

def leave_message(request): 
    log_user = User.objects.get(id = request.session['user'])
    posted_by_user = User.objects.get(id = request.POST['posted_by'])
    posted_for_user = User.objects.get(id = request.POST['posted_for'])
    user_id = posted_for_user.id
    message = request.POST['message']
    
    new_message = Message.objects.create(message = message, posted_by = posted_by_user, posted_for = posted_for_user)
    
    return redirect (f'/show_user_info/{user_id}')

def leave_comment(request): 
    log_user = User.objects.get(id = request.session['user'])
    posted_by_user = User.objects.get(id = request.POST['posted_by'])
    message = Message.objects.get(id = request.POST['message_id'])
    user_id = posted_by_user.id
    comment = request.POST['comment']
    
    new_comment = Comment.objects.create(comment = comment, posted_by = posted_by_user, message = message)
    
    return redirect (f'/show_user_info/{user_id}')

def show_edit_page(request, user_id):
    log_user = User.objects.get(id = request.session['user'])
    edit_user = User.objects.get(id = user_id)
    user_id = log_user.id
    context = {
        'user': edit_user,
        'log_user': log_user
    }
    return render (request, 'edit.html', context)

def edit_user_info(request, user_id):
    log_user = User.objects.get(id = request.session['user'])
    log_user_id = log_user.id
    edit_user = User.objects.get(id = user_id)
    email = request.POST['email']
    first_name = request.POST['first_name']
    last_name = request.POST['last_name']
    user_level = request.POST['user_level']
    description = request.POST['description']
    edit_user.email = email
    edit_user.first_name = first_name
    edit_user.last_name = last_name
    edit_user.user_level = user_level
    edit_user.description = description
    edit_user.save()
    return redirect (f'/show_user/{log_user_id}')

def edit_user_password(request, user_id): 
    log_user = User.objects.get(id = request.session['user'])
    log_user_id = log_user.id
    edit_user = User.objects.get(id = user_id)
    if request.POST['password'] is None: 
        return redirect (f'/edit/{user_id}')
    else:
        if request.POST['password'] == request.POST['confirm_password']:
            hashedpw = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt()).decode()
            edit_user.password = hashedpw
            return redirect (f'/edit/{user_id}')
        else:
            return redirect (f'/edit/{user_id}')
        
def delete(request, user_id): 
    log_user = User.objects.get(id = request.session['user'])
    log_user_id = log_user.id
    delete_user = User.objects.get(id = user_id)
    delete_user.delete()
    
    return redirect (f'/show_user/{log_user_id}')

def logout(request):
    del request.session['user']
    return redirect('/')