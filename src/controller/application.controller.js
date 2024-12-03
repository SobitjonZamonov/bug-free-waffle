import {
    createApplicationService,
    deleteApplicationService,
    getAllApplicationService,
    getByIdApplicationService,
    updateApplicationService,
} from '../service/index.service.js'
import { logger, statusCode } from '../utils/index.utils.js'
export const getAllApplicationController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/application/ METHOD : GET')
        const currentApplication = await getAllApplicationService(
            req.pagination,
        )
        if (!currentApplication) {
            res.status(statusCode.NOT_FOUND).send('Not Found')
        }
        return res.status(statusCode.OK).send({
            message: 'Ok',
            data: currentApplication,
        })
    } catch (error) {
        logger.error('Router /api/v1/application/all METHOD : GET')
        next(error)
    }
}
export const getByIdApplicationController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/application/:id METHOD : GET')
        const currentApplication = await getByIdApplicationService(
            req.params.id,
        )
        if (!currentApplication) {
            res.status(statusCode.NOT_FOUND).send('Not Found')
        }
        return res.status(statusCode.OK).send({
            message: 'Ok',
            data: currentApplication,
        })
    } catch (error) {
        logger.error('Router /api/v1/application/:id METHOD : GET')
        next(error)
    }
}
export const createApplicationController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/application/create METHOD : POST')
        const currentApplication = await createApplicationService(req.body)
        if (!currentApplication) {
            res.status(statusCode.BAD_REQUEST).send('Not Found')
        }
        return res.status(statusCode.CREATED).send({
            message: 'CREATED',
            data: currentApplication,
        })
    } catch (error) {
        logger.error('Router /api/v1/application/create METHOD : POST')
        next(error)
    }
}
export const updateIdApplicationController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/application/update/:id METHOD : PUT')
        const currentApplication = await updateApplicationService(
            req.params.id,
            req.body,
        )
        if (!currentApplication) {
            res.status(statusCode.NOT_FOUND).send('Not Found')
        }
        return res.status(statusCode.OK).send({
            message: 'UPDATED',
            data: currentApplication,
        })
    } catch (error) {
        logger.error('Router /api/v1/application/update/:id METHOD : PUT')
        next(error)
    }
}
export const deleteApplicationController = async (req, res, next) => {
    try {
        logger.info('Router /api/v1/application/delete/:id METHOD : DELETE')
        const currentApplication = await deleteApplicationService(req.params.id)

        if (!currentApplication) {
            res.status(statusCode.NOT_FOUND).send('Not Found')
        }
        return res.status(statusCode.OK).send({
            message: 'DELETED',
            data: currentApplication,
        })
    } catch (error) {
        logger.error('Router /api/v1/application/delete/:id METHOD : DELETE')
        next(error)
    }
}
