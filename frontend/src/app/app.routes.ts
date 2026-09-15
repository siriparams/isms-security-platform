import { Routes } from '@angular/router';

import { Login } from './login/login';
import { Home } from './home/home';
import { Inventory } from './inventory/inventory';
import { Audit } from './audit/audit';
import { authGuard } from './auth-guard';

export const routes: Routes = [

  // Login page
  {
    path: '',
    redirectTo: 'login',
    pathMatch: 'full'
  },

  {
    path: 'login',
    component: Login
  },

  // Home page - JWT required
  {
    path: 'home',
    component: Home,
    canActivate: [authGuard]
  },

  // Inventory page - JWT required
  {
    path: 'inventory',
    component: Inventory,
    canActivate: [authGuard]
  },

  // Audit page - JWT required
  {
    path: 'audit',
    component: Audit,
    canActivate: [authGuard]
  },

  // Any unknown URL goes to login
  {
    path: '**',
    redirectTo: 'login'
  }

];