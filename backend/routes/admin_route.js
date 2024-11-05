
import { Router } from "express";

import { login, signUp, listAdminUsers } from '../controllers/admin_controller.js';

import { hasPermission, isAuthenticated } from '../middlewares/auth.js';


export const adminRouter = Router();

adminRouter.post('/api/admin/register', signUp);
adminRouter.post('/api/admin/login', login);
adminRouter.get('/api/admin/users/list',isAuthenticated, hasPermission, listAdminUsers);