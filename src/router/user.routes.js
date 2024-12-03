import { Router } from 'express'
import {
    deleteUserById,
    getAllUsers,
    getUserById,
    searchUser,
    updateUserById,
} from '../controller/index.controller.js'
import {
    adminOrSelf,
    checkToken,
    pagination,
    roleGuard,
} from '../middleware/index.middleware.js'

export const userRouter = Router()

userRouter.get('/', checkToken, roleGuard('admin'), pagination, getAllUsers)
userRouter.get(
    '/search',
    checkToken,
    roleGuard('admin'),
    pagination,
    searchUser,
)
userRouter.get('/:id', checkToken, adminOrSelf('admin'), getUserById)
userRouter.put('/:id', checkToken, adminOrSelf('admin'), updateUserById)
userRouter.delete('/:id', checkToken, adminOrSelf('admin'), deleteUserById)
