import { Router } from 'express'
import {
    createCompanyController,
    deleteCompanyController,
    getAllCompanyController,
    getByIdCompanyController,
    searchCompanyController,
    updateIdCompanyController,
} from '../controller/index.controller.js'
import {
    checkToken,
    pagination,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { companiesSchema } from '../validations/companies.schema.js'

export const companyRouter = Router()

companyRouter.get('/', checkToken, pagination, getAllCompanyController)
companyRouter.get('/search', checkToken, pagination, searchCompanyController)
companyRouter.get('/:id', checkToken, getByIdCompanyController)
companyRouter.post(
    '/',
    checkToken,
    validationMiddleware(companiesSchema),
    createCompanyController,
)
companyRouter.put('/:id', checkToken, updateIdCompanyController)
companyRouter.delete('/:id', checkToken, deleteCompanyController)
