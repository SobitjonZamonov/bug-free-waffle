import { Router } from 'express'
import {
    createApplicationController,
    deleteApplicationController,
    getAllApplicationController,
    getByIdApplicationController,
    updateIdApplicationController,
} from '../controller/index.controller.js'
import {
    checkToken,
    pagination,
    roleGuard,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { applicationSchema } from '../validations/application.schema.js'
export const applicationRouter = Router()
applicationRouter.get(
    '/',
    checkToken,
    roleGuard('admin'),
    pagination,
    getAllApplicationController,
)
applicationRouter.get('/:id', checkToken, getByIdApplicationController)
applicationRouter.post(
    '/create',
    checkToken,
    validationMiddleware(applicationSchema),
    createApplicationController,
)
applicationRouter.put('/update/:id', checkToken, updateIdApplicationController)
applicationRouter.delete('/delete/:id', checkToken, deleteApplicationController)
