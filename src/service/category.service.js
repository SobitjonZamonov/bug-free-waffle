import { db } from '../database/index.database.js'
function checkData(data, errorMessage) {
    if (!data || data.length === 0) {
        throw new Error(errorMessage)
    }
}
export const getAllCategoriesService = async ({ skip, limit }) => {
    try {
        const data = await db
            .select('*')
            .from('categories')
            .offset(skip)
            .limit(limit)
        checkData(data, 'Categorys not found')
        return data
    } catch (error) {
        throw new Error(error.message)
    }
}
export const getCategoryByIdService = async (id) => {
    try {
        const data = await db.select('*').from('categories').where('id', id)
        checkData(data[0], 'Category not found')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const createCategoryService = async (body) => {
    try {
        const data = await db('categories')
            .insert({ ...body })
            .returning('*')
        checkData(data[0], 'Category not created')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const updateCategoryService = async (id, body) => {
    try {
        const data = await db('categories')
            .where('id', id)
            .update({ ...body })
            .returning('*')
        checkData(data[0], 'Category not updated')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const deleteCategoryService = async (id) => {
    try {
        const data = await db('categories').where('id', id).del().returning('*')
        checkData(data[0], 'Category not deleted')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
