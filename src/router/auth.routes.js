import { Router } from 'express'
import {
    changePassword,
    forgetPassword,
    getUserProfile,
    loginUser,
    logOut,
    registerUser,
    updateToken,
    verifyUser,
} from '../controller/index.controller.js'
import {
    checkToken,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import {
    loginSchema,
    registerSchema,
    verifySchema,
} from '../validations/index.schema.js'

export const authRouter = Router()

authRouter.post('/register', validationMiddleware(registerSchema), registerUser)
authRouter.post('/verify-otp', validationMiddleware(verifySchema), verifyUser)
authRouter.post('/login', validationMiddleware(loginSchema), loginUser)
authRouter.get('/me', checkToken, getUserProfile)
authRouter.get('/logout', checkToken, logOut)
authRouter.post('/refresh-token', updateToken)
authRouter.get('/forget/password', checkToken, forgetPassword)
authRouter.post('/change/password/:id', checkToken, changePassword)
