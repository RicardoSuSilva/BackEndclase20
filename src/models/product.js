import { Schema, model } from 'mongoose'
import  mongoosePaginate  from 'mongoose-paginate-v2'

const productSchema = new Schema({
    title: {
        type: String,
        required: true,
        index: true // genero indice a title
    },
    description: {
        type: String,
        required: true
    },
    stock: {
        type: Number,
        required: true
    },
    category: {
        type: String,
        required: true
    },
    status: {
        type: Boolean,
        default: true
    },
    code: {
        type: String,
        required: true,
        unique: true
    },
    price: {
        type: Number,
        required: true
    },
    thumbnail: {
        default: []
    }
})

productSchema.plugin(mongoosePaginate)

const productModel = model("products", productSchema)

export default productModel
