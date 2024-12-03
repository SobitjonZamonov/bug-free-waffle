import {
    getAllCategoriesService,
    getCategoryByIdService,
    createCategoryService,
    updateCategoryService,
    deleteCategoryService,
} from '../service/index.service.js'
import { logger, statusCode } from '../utils/index.utils.js'
export const getAllCategoriesCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/categories METHOD: GET`)
        const categories = await getAllCategoriesService(req.pagination)
        res.status(statusCode.OK).send({
            msg: 'OK',
            Categories: categories,
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/categories METHOD: GET,Error: ${error.message}`,
        )
        if (error.message === 'Categorys not found') {
            return res.status(statusCode.NOT_FOUND).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
export const getCategorysByIdCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/categories/${req.params.id} METHOD: GET`)
        const category = await getCategoryByIdService(req.params.id)
        res.status(statusCode.OK).send({
            msg: 'OK',
            Category: category,
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/categories/${req.params.id} METHOD: GET,Error: ${error.message}`,
        )
        if (error.message === 'Category not found') {
            return res.status(statusCode.NOT_FOUND).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
export const createCategoryCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/categories METHOD: POST`)
        const newCategory = await createCategoryService(req.body)
        res.status(statusCode.CREATED).send({
            msg: 'NEW CATEGORY',
            newCategory: newCategory,
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/categories METHOD: POST,Error: ${error.message}`,
        )
        if (error.message === 'Category not created') {
            return res.status(statusCode.BAD_REQUEST).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
export const updateCategoryCon = async (req, res, next) => {
    try {
        logger.info(`Routes: /api/v1/categories/${req.params.id} METHOD: PUT`)
        const updatedCategory = await updateCategoryService(
            req.params.id,
            req.body,
        )
        res.status(statusCode.OK).send({
            msg: 'UPDATED CATEGORY',
            updatedCategory: updatedCategory,
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/categories/${req.params.id} METHOD: PUT,Error: ${error.message}`,
        )
        if (error.message === 'Category not updated') {
            return res.status(statusCode.BAD_REQUEST).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
export const deleteCategoryCon = async (req, res, next) => {
    try {
        logger.info(
            `Routes: /api/v1/categories/${req.params.id} METHOD: DELETE`,
        )
        const deletedCategory = await deleteCategoryService(req.params.id)
        res.status(statusCode.OK).send({
            msg: 'DELETED CATEGORY',
            deletedCategory: deletedCategory,
        })
    } catch (error) {
        logger.error(
            `Routes: /api/v1/categories/${req.params.id} METHOD: DELETE,Error: ${error.message}`,
        )
        if (error.message === 'Category not deleted') {
            return res.status(statusCode.BAD_REQUEST).send({
                error: true,
                message: error.message,
            })
        }
        next(error.message)
    }
}
