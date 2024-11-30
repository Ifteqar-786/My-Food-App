import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

declare global {
    namespace Express {
        interface Request {
            id: string; // Assuming `id` is added to the request object for user identification
        }
    }
}

export const isAuthenticated = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const token = req.cookies.token; // Get the token from cookies
        if (!token) {
            // Token not found, send a 401 response
            res.status(401).json({
                success: false,
                message: "User not authenticated"
            });
            return; // Exit middleware
        }

        // Verify the token
        const decoded = jwt.verify(token, process.env.SECRET_KEY!) as jwt.JwtPayload;

        if (!decoded) {
            // If decoding failed, send a 401 response
            res.status(401).json({
                success: false,
                message: "Invalid token"
            });
            return; // Exit middleware
        }

        // Add user ID from the decoded token to the request
        req.id = decoded.userId;

        // Continue to the next middleware or route handler
        next();
    } catch (error) {
        // Handle unexpected errors
        res.status(500).json({
            message: "Internal server error"
        });
    }
};
