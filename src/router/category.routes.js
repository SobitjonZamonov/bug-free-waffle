import { Router } from 'express'
import {
    getAllCategoriesCon,
    getCategorysByIdCon,
    createCategoryCon,
    updateCategoryCon,
    deleteCategoryCon,
} from '../controller/category.controller.js'

import {
    checkToken,
    pagination,
    roleGuard,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { categoriesScheme } from '../validations/categories.scheme.js'

export const categoryRouter = Router()

categoryRouter.get(
    '/',
    checkToken,
    roleGuard('admin'),
    pagination,
    getAllCategoriesCon,
)
categoryRouter.get('/:id', checkToken, roleGuard('admin'), getCategorysByIdCon)
categoryRouter.post(
    '/',
    checkToken,
    roleGuard('admin'),
    validationMiddleware(categoriesScheme),
    createCategoryCon,
)
categoryRouter.put('/:id', checkToken, roleGuard('admin'), updateCategoryCon)
categoryRouter.delete('/:id', checkToken, roleGuard('admin'), deleteCategoryCon)
