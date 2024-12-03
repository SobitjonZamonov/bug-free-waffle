import { db } from '../database/index.database.js'

export const getAllApplicationService = async ({ skip, limit }) => {
    try {
        const data = await db
            .select('*')
            .from('application')
            .offset(skip)
            .limit(limit)
        if (!data) {
            throw new Error('Error')
        }
        return data
    } catch (error) {
        throw new Error(error)
    }
}
export const getByIdApplicationService = async (id) => {
    try {
        const data = await db
            .select('*')
            .from('application')
            .returning('*')
            .where('id', '=', id)
            .returning('*')
        if (!data[0]) {
            throw new Error('Error')
        }
        return data[0]
    } catch (error) {
        throw new Error(error)
    }
}
export const createApplicationService = async (body) => {
    try {
        const newData = await db('application')
            .insert({ ...body })
            .returning('*')
        if (!newData[0]) {
            throw new Error('Error')
        }
        return newData[0]
    } catch (error) {
        throw new Error(error)
    }
}
export const updateApplicationService = async (id, body) => {
    try {
        const updateData = await db('application')
            .where('id', '=', id)
            .update({ ...body })
            .returning('*')
        if (!updateData[0]) {
            throw new Error('Error')
        }
        return updateData[0]
    } catch (error) {
        throw new Error(error)
    }
}
export const deleteApplicationService = async (id) => {
    try {
        const deleteData = await db('application')
            .where('id', '=', id)
            .del()
            .returning('*')
        if (!deleteData[0]) {
            throw new Error('Error')
        }
        return deleteData[0]
    } catch (error) {
        throw new Error(error)
    }
}
