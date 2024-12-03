import {
    getAllJoblistsService,
    getJoblistByIdService,
    createJoblistService,
    updateJoblistService,
    deleteJoblistService,
    serachJobListService,
    getJobListsByCategoryService,
} from '../service/index.service.js'
import { logger, statusCode } from '../utils/index.utils.js'
export const getAllJobListsCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/joblists METHOD: GET`)
        const joblists = await getAllJoblistsService(req.pagination)
        res.status(statusCode.OK).send([...joblists])
    } catch (error) {
        logger.error(
            `Routes: /api/v1/joblists METHOD: GET,Error: ${error.message}`,
        )
        if (error.message === 'Joblists not found') {
            return res.status(statusCode.NOT_FOUND).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
export const getJobListsByIdCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/joblists/${req.params.id} METHOD: GET`)
        const joblist = await getJoblistByIdService(req.params.id)
        res.status(statusCode.OK).send({
            ...joblist,
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/joblists/${req.params.id} METHOD: GET,Error: ${error.message}`,
        )
        if (error.message === 'Joblist not found') {
            return res.status(statusCode.NOT_FOUND).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
export const getJobListsByCategory = async (req, res, next) => {
    try {
        const { jobs, success, error } = await getJobListsByCategoryService(
            req.params.id,
        )
        if (success) {
            return res.status(statusCode.OK).send({
                message: 'success',
                jobs,
            })
        }
        return res.status(statusCode.BAD_REQUEST).send({
            message: 'fail',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}
export const serachJobListCon = async (req, res, next) => {
    try {
        const { success, error, jobList } = await serachJobListService(
            req.query,
        )
        if (success && jobList.length > 0) {
            return res.status(statusCode.OK).send({
                message: 'success',
                jobList,
            })
        } else if (success) {
            return res.status(statusCode.OK).send({
                message: 'Jobs not found with this query',
            })
        }
        return res.status(statusCode.INTERNAL_SERVER_ERROR).send({
            message: 'fail',
            error,
        })
    } catch (error) {
        next(error)
    }
}
export const createJobListCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/joblists METHOD: POST`)
        const newJoblist = await createJoblistService(req.body)

        res.status(statusCode.CREATED).send({
            message: 'Job listing created',
            jobId: newJoblist.id,
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/joblists METHOD: POST,Error: ${error.message}`,
        )
        if (error.message === 'Joblist not created') {
            return res.status(statusCode.BAD_REQUEST).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
export const updateJobListCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/joblists/${req.params.id} METHOD: PUT`)
        const updatedJoblist = await updateJoblistService(
            req.params.id,
            req.body,
        )
        res.status(statusCode.OK).send({
            jobId: updatedJoblist.id,
            message: 'Job listing updated',
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/joblists/${req.params.id} METHOD: PUT,Error: ${error.message}`,
        )
        if (error.message === 'Joblist not updated') {
            return res.status(statusCode.BAD_REQUEST).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
export const deleteJobListCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/joblists/${req.params.id} METHOD: DELETE`)
        await deleteJoblistService(req.params.id)
        res.status(statusCode.OK).send({
            message: 'Job listing deleted',
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/joblists/${req.params.id} METHOD: DELETE,Error: ${error.message}`,
        )
        if (error.message === 'Joblist not deleted') {
            return res.status(statusCode.BAD_REQUEST).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
