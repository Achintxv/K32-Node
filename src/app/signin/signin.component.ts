import { Component } from '@angular/core';
import {
  FormBuilder,
  FormGroup,
  Validators,
  ReactiveFormsModule,
} from '@angular/forms';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { GoogleMap } from '@angular/google-maps';

@Component({
  selector: 'app-signin',
  standalone: true, 
  imports: [CommonModule, FormsModule, ReactiveFormsModule , GoogleMap],
  templateUrl: './signin.component.html',
  styleUrl: './signin.component.css',
})
export class SigninComponent {
  loginForm: FormGroup;
  showPassword: boolean = false;
  isRobot: boolean = false;
  keepSignedIn: boolean = false;
  recaptchaToken: string | null = null;


  constructor(private fb: FormBuilder) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required],
      isRobot: [false, Validators.requiredTrue], // Initially false, will be updated by reCAPTCHA
      keepSignedIn: [false],
    });
  }

  handleCaptchaResolved(token: string): void { // Corrected parameter type
    console.log('reCAPTCHA resolved:', token);
    this.isRobot = true;
    this.recaptchaToken = token;
    this.loginForm.patchValue({ isRobot: true });
  }

  handleCaptchaErrored(): void {
    console.error('reCAPTCHA error occurred.');
    this.isRobot = false;
    this.recaptchaToken = null;
    this.loginForm.patchValue({ isRobot: false });
    this.loginForm.controls['isRobot'].setErrors({ requiredTrue: true });
  }

  onLogin() {
    if (this.loginForm.valid && this.isRobot) {
      console.log('Form Submitted', this.loginForm.value);
    } else {
      console.warn('Form not valid or robot not checked');
    }
  }
}
