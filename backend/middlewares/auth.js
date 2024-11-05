import jwt from "jsonwebtoken";
import { ApiKeyModel } from "../models/api_model.js";
import { AdminModel } from "../models/admin_model.js";

export const isAuthenticated = (req, res, next) => {
  req.user = req.session.user || req.session.admin
  //Check if session has user
  if (req.session.user) {
    next();
  } else if (req.headers.authorization) {
    try {
      //Extract token from headers
      const token = req.headers.authorization.split(" ")[1];
      //Verify the token to get user and append to request
      req.user = jwt.verify(token, process.env.JWT_PRIVATE_KEY);
      //  console.log('Session User:', req.session.user);
      //  console.log('JWT User:', req.user);
      //all next function
      next();
    } catch (error) {
      return res.status(401).json({ error: "Token Expired" });
    }
  } else {
    res.status(401).json("User not authenticated");
  }
};

// To make sure that the API key is valid and allowed for the domain

export const validateDomain = async (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey) {
    return res.status(401).send("API key is missing");
  }

  try {
    const apiKeyDoc = await ApiKeyModel.findOne({ apiKey });
    if (!apiKeyDoc) {
      return res.status(401).send("Invalid API key");
    }

    const requestOrigin = req.get("origin") || req.hostname; // Check the request origin or hostname

    if (
      apiKeyDoc.domain.length > 0 &&
      !apiKeyDoc.domain.includes(requestOrigin)
    ) {
      return res.status(403).send("API key not allowed for this domain");
    }

    next(); // Proceed if the domain is valid
  } catch (error) {
    next(error);
  }
};

export const hasPermission = (action) => {
  return async (req, res, next) => {
    try {
      // Find user from the database
      const admin = await AdminModel.findById(req.auth.id);
      // Use the user role to find their permission
      const permission = permissions.find(value => value.role === user.role);
      if (!permission) {
        return res.status(403).json('No permision found!');
      }
      // Check if permission actions includes action
      if (permission.actions.includes(action)) {
        next();
      } else {
        res.status(403).json('Action not allowed!')
      }
    } catch (error) {
      next(error);
    }
  }
}