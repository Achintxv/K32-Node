import { Component } from '@angular/core';
import {
  FormBuilder,
  FormGroup,
  Validators,
  ReactiveFormsModule,
} from '@angular/forms';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-forget-password',
  standalone: true,
  imports: [CommonModule, FormsModule, ReactiveFormsModule],
  templateUrl: './forget-password.component.html',
  styleUrl: './forget-password.component.css',
})
export class ForgetPasswordComponent {
  loginForm: FormGroup;
  showPassword: boolean = false;
  isRobot: boolean = false;
  keepSignedIn: boolean = false;

  constructor(private fb: FormBuilder) {
    this.loginForm = this.fb.group({
      email: ['', [Validators.required, Validators.email]],
      password: ['', Validators.required],
      isRobot: [false, Validators.requiredTrue],
      keepSignedIn: [false],
    });
  }

  onLogin() {
    if (this.loginForm.valid && this.isRobot) {
      console.log('Form Submitted', this.loginForm.value);
    } else {
      console.warn('Form not valid or robot not checked');
    }
  }
}
