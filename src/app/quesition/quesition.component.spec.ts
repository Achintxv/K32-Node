import { ComponentFixture, TestBed } from '@angular/core/testing';

import { QuesitionComponent } from './quesition.component';

describe('QuesitionComponent', () => {
  let component: QuesitionComponent;
  let fixture: ComponentFixture<QuesitionComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [QuesitionComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(QuesitionComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
