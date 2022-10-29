from email.message import EmailMessage
from django.shortcuts import render, redirect,get_object_or_404
from .forms import RegisterForm,UserForm,UserProfileForm
from .models import Account, UserProfile
from django.contrib import messages, auth
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from orders.models import Order, OrderProduct

#verification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from cart.views import _cart_id
from cart.models import Cart,CartItem
import requests

# Create your views here.

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)

        if form.is_valid():
            first_name    = form.cleaned_data['first_name']
            last_name     = form.cleaned_data['last_name']
            email         = form.cleaned_data['email']
            phone_number  = form.cleaned_data['phone_number']
            password      = form.cleaned_data['password']
            username      = email.split('@')[0]

            user = Account.objects.create_user(first_name=first_name,last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()

            #Create User Profile
            profile = UserProfile()
            profile.user_id = user.id
            profile.profile_picture = 'default/default.png'
            profile.save()

            #user activate
            current_site = get_current_site(request)
            mail_subject = "Please activate your account"
            message      = render_to_string("accounts/account_verification_email.html",{
                'user':user,
                'domain':current_site,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            #messages.success(request, 'Thankyou for registering, please click on the verification link send to the registered email')
            return redirect('/accounts/login/?command=verification&email='+email)
        
    else:
        form = RegisterForm()
    context = {
        'form':form,
    }
    return render(request, 'accounts/register.html',context)


def login(request):
    if request.method == "POST":
        email     = request.POST['email']
        password  = request.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request)) #get cart using cart id present in session
                is_cart_item_exists = CartItem.objects.filter(cart=cart).exists()

                if is_cart_item_exists:
                    cart_item = CartItem.objects.filter(cart=cart)
                    
                    #getting product variation
                    product_variation = []
                    for item in cart_item:
                        variation = item.variations.all()
                        product_variation.append(list(variation))

                    #Get the cart item from the user to access the product variations
                    cart_item = CartItem.objects.filter(user=user)
                    ex_var_list = []
                    id=[]
                    for item in cart_item:
                        existing_variation = item.variations.all()
                        ex_var_list.append(list(existing_variation))
                        id.append(item.id)

                    # product_variation = [1,2,3,4,]
                    # ex_var_list = [1,3,5]
                    # Get the common
                    for pr in product_variation:
                        if pr in ex_var_list:
                            index = ex_var_list.index(pr)
                            item_id = id[index]
                            item = CartItem.objects.get(id=item_id)
                            item.quantity +=1
                            item.user = user
                            item.save()

                        else:
                            cart_item = CartItem.objects.filter(cart=cart)
                            for item in cart_item:
                                item.user = user
                                item.save()
            except:
                pass

            auth.login(request, user)
            messages.success(request, 'You logged In Successfully')
            url = request.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                
                #next=/cart/checlout/
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextpage = params['next']
                    return redirect(nextpage)
            except:
                return redirect('dashboard')
        else:
            messages.error(request, 'Invalid login credentials')
            return redirect('login')
    return render(request, 'accounts/login.html')


@login_required(login_url = 'login')
def logout(request):
    auth.logout(request)
    messages.success(request, 'Logout Successfully')
    return redirect('login')

def activate(request, uidb64, token):

    try :
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid) #give user object

    except(TypeError, ValueError,Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratualtions your account is activated ')
        return redirect('login')
    else:
            messages.error(request, 'Invalid link')
            return redirect('register')

      
@login_required(login_url = 'login')
def dashboard(request):
    orders = Order.objects.order_by('-created_at').filter(user_id=request.user.id, is_ordered=True)
    orders_count = orders.count()
    userprofile = UserProfile.objects.get(user_id=request.user)

    context = {
        'orders_count':orders_count,
        'userprofile':userprofile,
    }
    return render(request,'accounts/dashboard.html',context)


def forgotpassword(request):
    if request.method == 'POST':
        email = request.POST['email']

        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)

            #password reset
            current_site = get_current_site(request)
            mail_subject = "Reset your password"
            message      = render_to_string("accounts/reset_password_email.html",{
                'user':user,
                'domain':current_site,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':default_token_generator.make_token(user),
            })
            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            messages.success(request, 'Password reset link is sent to your registered email address')
            return redirect('login')

        else:
            messages.error(request, 'User does not exists.')
            return redirect('forgotpassword')

    return render(request,'accounts/forgotpassword.html')

def resetpassword_validate(request, uidb64, token):

    try :
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid) #give user object

    except(TypeError, ValueError,Account.DoesNotExist):
        user = None


    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password ')
        return redirect('resetpassword')
    else:
            messages.error(request, 'The link has been expired')
            return redirect('login')


def resetpassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)# the function take the password and hash it and save also
            user.save()
            messages.success(request, 'Password change successfully ')
            return redirect('login')

        else:
            messages.error(request, 'Password does not match')
            return redirect('resetpassword')

    else:
        return render(request,'accounts/resetpassword.html')


def my_orders(request):
    orders = Order.objects.filter(user_id=request.user.id, is_ordered=True).order_by('-created_at')
    context = {
        'orders':orders,
    }
    return render(request, 'accounts/my_orders.html',context)


@login_required(login_url='login')
def edit_profile(request):
    userprofile = get_object_or_404(UserProfile, user=request.user)
    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=request.user)
        profile_form = UserProfileForm(request.POST, request.FILES, instance=userprofile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile has been updated.')
            return redirect('edit_profile')
    else:
        user_form = UserForm(instance=request.user)
        profile_form = UserProfileForm(instance=userprofile)
    context = {
        'user_form': user_form,
        'profile_form': profile_form,
        'userprofile': userprofile,
    }
    return render(request, 'accounts/edit_profile.html', context)


@login_required(login_url='login')
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST['current_password']
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']

        user = Account.objects.get(username__exact=request.user.username)

        if new_password == confirm_password:
            success = user.check_password(current_password)

            if success:
                user.set_password(new_password)
                user.save()
                #auth.logout(request)  To logout when password change
                messages.success(request, 'Password has been updated.')
                return redirect('change_password')
            else:
                messages.error(request, 'Please enter valid current password.')
                return redirect('change_password')
        else:
            messages.error(request, 'Password does not match.')
            return redirect('change_password')

    return render(request,'accounts/change_password.html')



def order_detail(request, order_id):
    order_detail = OrderProduct.objects.filter(order__order_number=order_id)
    order = Order.objects.get(order_number=order_id)
    subtotal = 0
    for i in order_detail:
        subtotal+=i.product_price*i.quantity
    context = {
        'order_detail':order_detail,
        'order':order,
        'subtotal':subtotal,
    }
    return render(request,'accounts/order_detail.html',context)