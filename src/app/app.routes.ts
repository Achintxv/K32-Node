import { Route } from '@angular/router';
import { MyComponentComponent } from './my-component/my-component.component';
import { HomeComponent } from './home/home.component';
import { SigninComponent } from './signin/signin.component';
import { SignupComponent } from './signup/signup.component';
import { ForgetPasswordComponent } from './forget-password/forget-password.component';

export const routes: Route[] = [
  { path: '', component: HomeComponent },
  { path: 'component', component: MyComponentComponent },
  { path: 'signin', component: SigninComponent },
  { path: 'signup', component: SignupComponent },
  { path: 'forgetPassword', component: ForgetPasswordComponent },
  { path: '**', redirectTo: '', pathMatch: 'full' },
];
