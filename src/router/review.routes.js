import { Router } from 'express'
import {
    createReviewController,
    deleteReviewController,
    getAllReviewController,
    getByIdReviewController,
    updateIdReviewController,
} from '../controller/index.controller.js'
import {
    checkToken,
    pagination,
    roleGuard,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { reviewSchema } from '../validations/review.schema.js'

export const reviewRouter = Router()

reviewRouter.get(
    '/',
    checkToken,
    roleGuard('admin'),
    pagination,
    getAllReviewController,
)
reviewRouter.get(
    '/:id',
    checkToken,
    roleGuard('admin'),
    getByIdReviewController,
)
reviewRouter.post(
    '/',
    checkToken,
    validationMiddleware(reviewSchema),
    createReviewController,
)
reviewRouter.put('/:id', checkToken, updateIdReviewController)
reviewRouter.delete('/:id', checkToken, deleteReviewController)
