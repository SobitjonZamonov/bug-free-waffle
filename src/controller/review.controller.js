import {
    createReviewService,
    deleteReviewService,
    getAllReviewService,
    getByIReviewService,
    updateReviewService,
} from '../service/index.service.js'
import { logger, statusCode } from '../utils/index.utils.js'
export const getAllReviewController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/review/ METHOD : GET')
        const currentReview = await getAllReviewService(req.pagination)
        if (!currentReview) {
            return res.status(statusCode.NOT_FOUND).send('Not found!!!')
        }
        return res.status(statusCode.OK).send({
            message: 'Ok',
            data: currentReview,
        })
    } catch (error) {
        logger.error('Router /api/v1/review/ METHOD : GET')
        next(error)
    }
}
export const getByIdReviewController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/review/:id METHOD : GET')
        const currentReview = await getByIReviewService(req.params.id)
        if (!currentReview) {
            return res.status(statusCode.NOT_FOUND).send('Not found!!!')
        }
        return res.status(statusCode.OK).send({
            message: 'Ok',
            data: currentReview,
        })
    } catch (error) {
        logger.error('Router /api/v1/review/:id METHOD : GET')
        next(error)
    }
}
export const createReviewController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/review/create METHOD : POST')

        const currentReview = await createReviewService(req.body, req.user.id)

        if (!currentReview) {
            return res.status(statusCode.NOT_FOUND).send('Not found!!!')
        }
        return res.status(statusCode.CREATED).send({
            message: 'CREATED',
            data: currentReview,
        })
    } catch (error) {
        logger.error('Router /api/v1/review/create METHOD : POST')
        next(error)
    }
}
export const updateIdReviewController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/review/update/:id METHOD : PUT')
        const currentReview = await updateReviewService(req.params.id, req.body)
        if (!currentReview) {
            return res.status(statusCode.NOT_FOUND).send('Not found!!!')
        }
        return res.status(statusCode.OK).send({
            message: 'UPDATED',
            data: currentReview,
        })
    } catch (error) {
        logger.error('Router /api/v1/review/update/:id METHOD : PUT')
        next(error)
    }
}
export const deleteReviewController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/review/delete/:id METHOD : DELETE')
        const currentReview = await deleteReviewService(req.params.id)
        if (!currentReview) {
            return res.status(statusCode.NOT_FOUND).send('Not found!!!')
        }
        return res.status(statusCode.OK).send({
            message: 'Review deleted',
        })
    } catch (error) {
        logger.error('Router /api/v1/review/delete/:id METHOD : DELETE')
        next(error)
    }
}
