import { Component } from '@angular/core';
import { NavbarComponent } from '../navbar/navbar.component';
import { MainPageComponent } from '../main-page/main-page.component';
import { QuesitionComponent } from '../quesition/quesition.component';
import { FooterComponent } from '../footer/footer.component';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [NavbarComponent, MainPageComponent, QuesitionComponent ,FooterComponent],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css'
})
export class HomeComponent {

}
