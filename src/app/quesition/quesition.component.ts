import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-quesition', 
  standalone: true,
  imports: [CommonModule], // <-- Add this line
  templateUrl: './quesition.component.html',
  styleUrl: './quesition.component.css'
})
export class QuesitionComponent {
  faqs = [
    {
      question: 'How to Subscribe to an IPO?',
      answer: [
        'Step 1: Login to your respective service provider.',
        'Step 2: Click on the IPO button.',
        'Step 3: Select the IPO you want to bid and enter the relevant details.',
        'Step 4: Your subscription will be completed once you make the payment or give permission.'
      ]
    },
    {
      question: 'Should I buy an IPO first day?',
      answer: ['Add answer here']
    },
    {
      question: 'How do you know if an IPO is good?',
      answer: ['Add answer here']
    },
    {
      question: 'How to check IPO start date?',
      answer: ['Add answer here']
    },
    {
      question: 'What is issue size?',
      answer: ['Add answer here']
    },
    {
      question: 'How many shares in a lot?',
      answer: ['Add answer here']
    },
    {
      question: 'How is the lot size calculated?',
      answer: ['Add answer here']
    },
    {
      question: 'Who decides the IPO price band?',
      answer: ['Add answer here']
    },
    {
      question: 'What is IPO GMP?',
      answer: ['Add answer here']
    },
    {
      question: 'How many lots should I apply for IPO?',
      answer: ['Add answer here']
    }
  ];

}
