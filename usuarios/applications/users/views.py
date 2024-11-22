from django.core.mail import send_mail
from django.contrib.auth.forms import PasswordResetForm
from django.urls import reverse_lazy, reverse
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import redirect, get_object_or_404, render

from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.core.exceptions import ValidationError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.contrib import messages
from django.contrib.auth.hashers import make_password


from django.views.generic import (
    View,
    CreateView,
    TemplateView
)
from django.views.generic.edit import (
    FormView
)
from .forms import *
from .models import User
from .functions import code_generator
# Create your views here.
class UserRegisterView(FormView):
    template_name = 'users/register.html'
    form_class = UserRegisterForm
    success_url = '/'
    
    def form_valid(self, form):
        codigo = code_generator()
        usuario = User.objects.create_user(
            form.cleaned_data['username'],
            form.cleaned_data['email'],
            form.cleaned_data['password1'],
            nombres = form.cleaned_data['nombres'],
            apellidos = form.cleaned_data['apellidos'],
            genero = form.cleaned_data['genero'],
            codregistro = codigo
        )
        #enviar el codigo al email del user
        asunto = 'Confirmacion de email'
        mensaje = 'El codigo de verificacion es: '+ codigo
        email_remitente = 'no-reply@example.com'
        send_mail(asunto, mensaje, email_remitente, [form.cleaned_data['email'],])
        #redirigir a pantalla de validacion
        return HttpResponseRedirect(
            reverse(
                'users_app:user-verification',
                kwargs={'pk': usuario.id}
            )
        )

class LoginUser(FormView):
    template_name = 'users/login.html'
    form_class = LoginForm
    success_url = reverse_lazy('home_app:panel')
    
    def form_valid(self, form):
        user = authenticate(
            username = form.cleaned_data['username'],
            password = form.cleaned_data['password']
        )
        login(self.request, user)
        return super(LoginUser, self).form_valid(form)
    
class LogoutView(View):
    def get(self, request, *args, **kwargs): 
        logout(request) 
        return HttpResponseRedirect(
            reverse(
                'users_app:user-login'
            )
        )
        
class UpdatePwView(LoginRequiredMixin, FormView):
    template_name = 'users/update.html'
    form_class = UpdatePasswordForm
    success_url = reverse_lazy('users_app:user-login')
    login_url = reverse_lazy('users_app:user-login')
    
    def form_valid(self, form):
        usuario = self.request.user
        user = authenticate(
            username = usuario.username,
            password = form.cleaned_data['password1']
        )
        if user:
            new_password = form.cleaned_data['password2']
            usuario.set_password(new_password)
            usuario.save()
        
        return super(UpdatePwView, self).form_valid(form)
    
class CodeVerificationView(FormView):
    template_name = 'users/verification.html'
    form_class = VerificationForm
    success_url = reverse_lazy('users_app:user-login')
    
    def get_form_kwargs(self):
        kwargs = super(CodeVerificationView, self).get_form_kwargs()
        kwargs.update(
            {
                'pk': self.kwargs['pk']
            }
        )
        return kwargs
    
    def form_valid(self, form):
        
        User.objects.filter(
            id=self.kwargs['pk']
        ).update(
            is_active=True
        )
        return super(CodeVerificationView, self).form_valid(form)
 
 
 

 
 
 
 
 
   
#admin    
class AdministrarUsuariosView(UserPassesTestMixin, TemplateView):
    template_name = "users/admin.html"

    def test_func(self):
        # Permitir acceso solo a superusuarios
        return self.request.user.is_superuser

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Agregar los usuarios al contexto para mostrarlos en la plantilla
        context['usuarios'] = User.objects.filter(is_staff=False)
        return context
    
    def post(self, request, *args, **kwargs):
        user_id = request.POST.get('user_id')  # Obtener el ID del usuario desde el formulario
        user = get_object_or_404(User, pk=user_id, is_superuser=False)  # Excluir superusuarios
        user.is_active = not user.is_active  # Cambiar el estado de activación
        user.save()
        return redirect('users_app:user-admin')  # Redirigir a la misma página

    def handle_no_permission(self):
        # Redirigir a otra página si no tiene permiso
        return redirect('home_app:panel')  # Redirige al home o muestra un mensaje

class AdminRegisterView(UserPassesTestMixin, FormView):
    template_name = 'users/register_admin.html'
    form_class = UserRegisterForm
    success_url = reverse_lazy('users_app:user-admin')
    
    def form_valid(self, form):
        codigo = code_generator()
        usuario = User.objects.create_user(
            form.cleaned_data['username'],
            form.cleaned_data['email'],
            form.cleaned_data['password1'],
            nombres = form.cleaned_data['nombres'],
            apellidos = form.cleaned_data['apellidos'],
            genero = form.cleaned_data['genero'],
            codregistro = codigo
        )
        #enviar el codigo al email del user
        asunto = 'Confirmacion de email'
        mensaje = 'El codigo de verificacion es: '+ codigo
        email_remitente = 'no-reply@example.com'
        send_mail(asunto, mensaje, email_remitente, [form.cleaned_data['email'],])
        #redirigir a pantalla de validacion
        return HttpResponseRedirect(
            reverse(
                'users_app:admin-verification',
                kwargs={'pk': usuario.id}
            )
        )
    def test_func(self):
        # Permitir acceso solo a superusuarios
        return self.request.user.is_superuser

    def handle_no_permission(self):
        # Redirigir si no tiene permisos
        return redirect('home_app:panel')
 
class CodeAdminVerificationView(FormView):
    template_name = 'users/verification_admin.html'
    form_class = VerificationForm
    success_url = reverse_lazy('users_app:user-admin')
    
    def get_form_kwargs(self):
        kwargs = super(CodeAdminVerificationView, self).get_form_kwargs()
        kwargs.update(
            {
                'pk': self.kwargs['pk']
            }
        )
        return kwargs
    
    def form_valid(self, form):
        
        User.objects.filter(
            id=self.kwargs['pk']
        ).update(
            is_active=True,
            is_superuser=True,
            is_staff=True
        )
        return super(CodeAdminVerificationView, self).form_valid(form)
 
 
#recuperar contraseña
User = get_user_model()

class RequestPasswordResetView(FormView):
    template_name = 'users/request_reset.html'
    form_class = RequestPasswordResetForm
    success_url = reverse_lazy('users_app:reset-password')

    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        try:
            # Buscar usuario por username
            user = User.objects.get(username=username)
            self.request.session['reset_user_id'] = user.id  # Guardar usuario en la sesión
            return super().form_valid(form)
        except User.DoesNotExist:
            messages.error(self.request, 'El usuario no existe.')
            return redirect('users_app:request-reset-password')


class ResetPasswordView(FormView):
    template_name = 'users/reset_password.html'
    form_class = ResetPasswordForm
    success_url = reverse_lazy('users_app:user-login')

    def form_valid(self, form):
        user_id = self.request.session.get('reset_user_id')
        if not user_id:
            messages.error(self.request, 'Primero solicita el restablecimiento de contraseña.')
            return redirect('users_app:request-reset-password')

        try:
            user = User.objects.get(id=user_id)
            new_password = form.cleaned_data['new_password']
            user.set_password(new_password)
            user.save()
            del self.request.session['reset_user_id']  # Limpiar la sesión
            messages.success(self.request, 'Contraseña restablecida correctamente.')
            return super().form_valid(form)
        except User.DoesNotExist:
            messages.error(self.request, 'El usuario no existe.')
            return redirect('users_app:request-reset-password')
 
 
 

#contraseña
#class CustomPasswordResetView(PasswordResetView):
#    template_name = 'users/password_reset_form.html'
#    email_template_name = 'users/password_reset_email.html'
#    success_url = reverse_lazy('users:password_reset_done')
#    form_class = PasswordResetForm

#    def form_valid(self, form):
        # Verifica que el correo existe en el sistema
#        email = form.cleaned_data['email']
#        if not User.objects.filter(email=email).exists():
#            form.add_error('email', 'No se encontró un usuario con este correo electrónico.')
#            return self.form_invalid(form)
        # Lógica predeterminada para enviar el correo
#        return super().form_valid(form)
    
#class CustomPasswordResetDoneView(PasswordResetDoneView):
#    template_name = 'users/password_reset_done.html'

#    def get_context_data(self, **kwargs):
#        context = super().get_context_data(**kwargs)
#        context['message'] = "Revisa tu correo para el enlace de restablecimiento."
#        return context
    
#class CustomPasswordResetConfirmView(PasswordResetConfirmView):
#    template_name = 'users/password_reset_confirm.html'
#    success_url = reverse_lazy('users:password_reset_complete')

#    def form_valid(self, form):
        # Lógica para guardar la nueva contraseña
#        user = form.save()
        # Aquí puedes agregar lógica personalizada, como enviar una notificación al usuario
#        return super().form_valid(form)

#    def get_user(self, uidb64):
#        try:
#            uid = urlsafe_base64_decode(uidb64).decode()
#            return User.objects.get(pk=uid)
#        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#            return None

#    def dispatch(self, *args, **kwargs):
#        user = self.get_user(self.kwargs['uidb64'])
#        token = self.kwargs['token']

#        if user is None or not default_token_generator.check_token(user, token):
            # Maneja el caso en el que el enlace no es válido
#            return self.render_to_response({'invalid_link': True})

#        return super().dispatch(*args, **kwargs)
    
#class CustomPasswordResetCompleteView(PasswordResetCompleteView):
#    template_name = 'users/password_reset_complete.html'

#    def get_context_data(self, **kwargs):
#        context = super().get_context_data(**kwargs)
#        context['message'] = "Tu contraseña ha sido restablecida exitosamente."
#        return context
    
# Función para enviar el correo de restablecimiento
#def send_password_reset_email(user, token, uidb64):
#    context = {
#        'user': user,
#        'uid': uidb64,
#        'token': token,
#        'domain': 'example.com',  # Puedes obtener esto dinámicamente si lo necesitas
#        'protocol': 'https',  # Cambia esto según tu configuración
#    }
#    email_body = render_to_string('users/password_reset_email.html', context)
#    send_mail(
#        'Password Reset',
#        email_body,
#        'from@example.com',  # Dirección de correo del remitente
#        [user.email]
#    )

# Vista para manejar el formulario de restablecimiento de contraseña
#def custom_password_reset(request):
#    if request.method == "POST":
#        form = PasswordResetForm(request.POST)
#        if form.is_valid():
#            # Obtener el usuario relacionado con el correo proporcionado
#            email = form.cleaned_data['email']
#            users = form.get_users(email)
#            for user in users:
#                # Generar el UID y el token
#                uidb64 = urlsafe_base64_encode(user.pk.encode())
#                token = default_token_generator.make_token(user)

#                # Llamar a la función para enviar el correo
#                send_password_reset_email(user, token, uidb64)

#            return HttpResponse("Email sent")
#    else:
#        form = PasswordResetForm()

#    return render(request, 'users/password_reset_form.html', {'form': form})    
