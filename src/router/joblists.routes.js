import { Router } from 'express'
import {
    getAllJobListsCon,
    getJobListsByIdCon,
    createJobListCon,
    updateJobListCon,
    deleteJobListCon,
    serachJobListCon,
    getJobListsByCategory,
} from '../controller/index.controller.js'
import {
    checkToken,
    pagination,
    roleGuard,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { joblistingScheme } from '../validations/index.schema.js'
export const joblistRouter = Router()
joblistRouter.get('/', checkToken, pagination, getAllJobListsCon)
joblistRouter.get(
    '/category/:id',
    checkToken,
    pagination,
    getJobListsByCategory,
)
joblistRouter.get('/search', checkToken, pagination, serachJobListCon)
joblistRouter.get('/:id', checkToken, getJobListsByIdCon)
joblistRouter.post(
    '/',
    checkToken,
    validationMiddleware(joblistingScheme),
    createJobListCon,
)
joblistRouter.put('/:id', checkToken, updateJobListCon)
joblistRouter.delete('/:id', checkToken, roleGuard('admin'), deleteJobListCon)
