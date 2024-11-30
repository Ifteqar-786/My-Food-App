import { Request, Response } from "express";
import uploadImageOnCloudinary from "../utils/imageUpload";
import { Menu } from "../models/menu.model";
import { Restaurant } from "../models/restaurant.model";
import mongoose, { ObjectId } from "mongoose";

// Add Menu
export const addMenu = async (req: Request, res: Response): Promise<void> => {
    try {
        const { name, description, price } = req.body;
        const file = req.file;

        if (!file) {
            res.status(400).json({
                success: false,
                message: "Image is required",
            });
            return;
        }

        const imageUrl = await uploadImageOnCloudinary(file as Express.Multer.File);

        const menu = await Menu.create({
            name,
            description,
            price,
            image: imageUrl,
        });

        const restaurant = await Restaurant.findOne({ user: req.id });

        if (restaurant) {
            // Ensure the restaurant has menus array and is of correct type
            (restaurant.menus as mongoose.Schema.Types.ObjectId[]).push(menu._id as mongoose.Schema.Types.ObjectId);
            await restaurant.save();
        }

        res.status(201).json({
            success: true,
            message: "Menu added successfully",
            menu,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};

// Edit Menu
export const editMenu = async (req: Request, res: Response): Promise<void> => {
    try {
        const { id } = req.params;
        const { name, description, price } = req.body;
        const file = req.file;

        // Ensure that the menu exists
        const menu = await Menu.findById(id);
        
        // Check if menu is null before proceeding
        if (!menu) {
            res.status(404).json({
                success: false,
                message: "Menu not found!",
            });
            return;
        }

        if (name) menu.name = name;
        if (description) menu.description = description;
        if (price) menu.price = price;

        if (file) {
            const imageUrl = await uploadImageOnCloudinary(file as Express.Multer.File);
            menu.image = imageUrl;
        }

        await menu.save();

        res.status(200).json({
            success: true,
            message: "Menu updated",
            menu,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Internal server error" });
    }
};