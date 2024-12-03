import { db } from '../database/index.database.js'
function checkData(data, errorMessage) {
    if (!data || data.length === 0) {
        throw new Error(errorMessage)
    }
}
export const getAllWishlistsService = async ({ skip, limit }) => {
    try {
        const data = await db
            .select('*')
            .from('wishlist')
            .offset(skip)
            .limit(limit)
        checkData(data, 'Wishlists not found')
        return data
    } catch (error) {
        ;``
        throw new Error(error.message)
    }
}
export const getWishlistByIdService = async (id) => {
    try {
        const data = await db.select('*').from('wishlist').where('id', id)
        checkData(data[0], 'Wishlist not found')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const createWishlistService = async (body) => {
    try {
        const data = await db('wishlist')
            .insert({ ...body })
            .returning('*')
        checkData(data[0], 'Wishlist not created')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const updateWishlistService = async (id, body) => {
    try {
        const data = await db('wishlist')
            .update({ ...body })
            .where('id', id)
            .returning('*')
        checkData(data[0], 'Wishlist not updated')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
export const deleteWishlistService = async (id) => {
    try {
        const data = await db('wishlist').where('id', id).del().returning('*')
        checkData(data[0], 'Wishlist not deleted')
        return data[0]
    } catch (error) {
        throw new Error(error.message)
    }
}
