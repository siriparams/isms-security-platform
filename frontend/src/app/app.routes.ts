import { Routes } from '@angular/router';

import { Login } from './login/login';
import { Home } from './home/home';
import { Inventory } from './inventory/inventory';
import { Audit } from './audit/audit';


export const routes: Routes = [

  // =====================================================
  // LOGIN
  // =====================================================

  {
    path: 'login',
    component: Login
  },


  // =====================================================
  // HOME
  // =====================================================

  {
    path: 'home',
    component: Home
  },


  // =====================================================
  // ASSET INVENTORY
  // =====================================================

  {
    path: 'inventory',
    component: Inventory
  },


  // =====================================================
  // AUDIT DETAILS
  // Example: /audit/3
  // =====================================================

  {
    path: 'audit/:id',
    component: Audit
  },


  // =====================================================
  // AUDIT MAIN PAGE
  // =====================================================

  {
    path: 'audit',
    component: Audit
  },


  // =====================================================
  // DEFAULT
  // =====================================================

  {
    path: '',
    redirectTo: 'login',
    pathMatch: 'full'
  },


  // =====================================================
  // UNKNOWN URL
  // =====================================================

  {
    path: '**',
    redirectTo: 'login'
  }

];