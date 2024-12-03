import { db } from '../database/index.database.js'

export const getAllReviewService = async ({ skip, limit }) => {
    try {
        const data = await db
            .select('*')
            .from('review')
            .returning('*')
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
export const getByIReviewService = async (id) => {
    try {
        const data = await db('review').select('*').where('id', id)
        if (!data[0]) {
            throw new Error('Review not found')
        }
        return data[0]
    } catch (error) {
        throw new Error(error)
    }
}
export const createReviewService = async (body, user_id) => {
    try {
        body.user_id = user_id
        const newData = await db('review')
            .insert({ ...body })
            .returning('*')
        if (!newData[0]) {
            throw new Error('Error')
        }
        return newData
    } catch (error) {
        throw new Error(error)
    }
}
export const updateReviewService = async (id, body) => {
    try {
        const { comment, status, raiting } = body
        const updatedReview = { comment, status, raiting }
        const updateData = await db('review')
            .where('id', '=', id)
            .update(updatedReview)
            .returning('*')
        if (!updateData[0]) {
            throw new Error('Error')
        }
        return updateData[0]
    } catch (error) {
        throw new Error(error)
    }
}
export const deleteReviewService = async (id) => {
    try {
        await db('review').where('id', '=', id).del()
        return true
    } catch (error) {
        throw new Error(error)
    }
}
