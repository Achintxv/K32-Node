// import { Component } from '@angular/core';

// @Component({
//   selector: 'app-main-page',
//   standalone: true,
//   imports: [],
//   templateUrl: './main-page.component.html',
//   styleUrl: './main-page.component.css'
// })
// export class MainPageComponent {

// }

// import { Component } from '@angular/core';
// import { CommonModule } from '@angular/common';

// @Component({
//   selector: 'app-main-page',
//   standalone: true,
//   imports: [CommonModule], // <-- Add this line
//   templateUrl: './main-page.component.html',
// })
// export class MainPageComponent {}

import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';

@Component({
  selector: 'app-main-page',
  standalone: true,
  imports: [CommonModule], // <-- Add this line
  templateUrl: './main-page.component.html',
  styleUrl: './main-page.component.css',
})
export class MainPageComponent {
  ipoList = [
    {
      logo: 'assets/nova.png',
      company: 'Nova Agritech Ltd.',
      priceBand: 'Rs 39 - 41',
      open: '2024-01-22',
      close: '2024-01-24',
      issueSize: '143.81 Cr.',
      issueType: 'Book Built',
      listingDate: '2024-01-30',
    },
    {
      logo: 'assets/epack.png',
      company: 'EPACK Durable Ltd.',
      priceBand: 'Rs 218 - 230',
      open: '2024-01-19',
      close: '2024-01-23',
      issueSize: '640.05 Cr.',
      issueType: 'Book Built',
      listingDate: '2024-01-29',
    },
    {
      logo: 'assets/rkswamy.png',
      company: 'RK Swamy Ltd.',
      priceBand: 'Not Issued',
      open: 'Not Issued',
      close: 'Not Issued',
      issueSize: 'Not Issued',
      issueType: 'Book Built',
      listingDate: 'Not Issued',
    },
  ];
}
