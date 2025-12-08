const express = require('express');
const router = express.Router();  // Use express.Router()
const roleController = require('../controllers/role.controller');
const authController = require('../controllers/auth.controller');

// All routes require authentication
router.use(authController.protect);

// ==================== PERMISSION ROUTES ====================

/**
 * @swagger
 * tags:
 *   name: Permissions
 *   description: Permission management
 */

/**
 * @swagger
 * /roles/permissions:
 *   get:
 *     summary: Get all permissions
 *     tags: [Permissions]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: category
 *         schema:
 *           type: string
 *         description: Filter by category
 *       - in: query
 *         name: module
 *         schema:
 *           type: string
 *         description: Filter by module
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in name or description
 *     responses:
 *       200:
 *         description: Permissions retrieved successfully
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 */
router.get('/permissions', 
  authController.hasPermission('view_permissions'),
  roleController.getAllPermissions
);

/**
 * @swagger
 * /roles/permissions:
 *   post:
 *     summary: Create a new permission
 *     tags: [Permissions]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - description
 *               - category
 *               - module
 *             properties:
 *               name:
 *                 type: string
 *                 example: "create_user"
 *               description:
 *                 type: string
 *                 example: "Can create new users"
 *               category:
 *                 type: string
 *                 example: "user_management"
 *               module:
 *                 type: string
 *                 example: "users"
 *               isDefault:
 *                 type: boolean
 *                 example: false
 *     responses:
 *       201:
 *         description: Permission created successfully
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 *       409:
 *         description: Permission already exists
 */
router.post('/permissions', 
  authController.hasPermission('create_permission'),
  roleController.createPermission
);

// ==================== ROLE ROUTES ====================

/**
 * @swagger
 * tags:
 *   name: Roles
 *   description: Role management
 */

/**
 * @swagger
 * /roles:
 *   get:
 *     summary: Get all roles
 *     tags: [Roles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: search
 *         schema:
 *           type: string
 *         description: Search in name or description
 *       - in: query
 *         name: isActive
 *         schema:
 *           type: boolean
 *         description: Filter by active status
 *     responses:
 *       200:
 *         description: Roles retrieved successfully
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 */
router.get('/', 
  authController.hasPermission('view_roles'),
  roleController.getAllRoles
);

/**
 * @swagger
 * /roles/{id}:
 *   get:
 *     summary: Get a single role
 *     tags: [Roles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Role ID
 *     responses:
 *       200:
 *         description: Role retrieved successfully
 *       404:
 *         description: Role not found
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 */
router.get('/:id', 
  authController.hasPermission('view_roles'),
  roleController.getRole
);

/**
 * @swagger
 * /roles:
 *   post:
 *     summary: Create a new role
 *     tags: [Roles]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - description
 *             properties:
 *               name:
 *                 type: string
 *                 example: "Manager"
 *               description:
 *                 type: string
 *                 example: "Manager role with limited admin privileges"
 *               permissions:
 *                 type: array
 *                 items:
 *                   type: string
 *                 example: ["view_users", "create_user", "update_user"]
 *               hierarchyLevel:
 *                 type: number
 *                 example: 5
 *               isDefault:
 *                 type: boolean
 *                 example: false
 *     responses:
 *       201:
 *         description: Role created successfully
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 *       409:
 *         description: Role already exists
 */
router.post('/', 
  authController.hasPermission('create_role'),
  roleController.createRole
);

/**
 * @swagger
 * /roles/{id}:
 *   put:
 *     summary: Update a role
 *     tags: [Roles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Role ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 example: "Senior Manager"
 *               description:
 *                 type: string
 *                 example: "Updated description"
 *               permissions:
 *                 type: array
 *                 items:
 *                   type: string
 *                 example: ["view_users", "create_user", "update_user", "delete_user"]
 *               hierarchyLevel:
 *                 type: number
 *                 example: 6
 *               isDefault:
 *                 type: boolean
 *                 example: false
 *               isActive:
 *                 type: boolean
 *                 example: true
 *     responses:
 *       200:
 *         description: Role updated successfully
 *       400:
 *         description: Invalid input
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 *       404:
 *         description: Role not found
 */
router.put('/:id', 
  authController.hasPermission('update_role'),
  roleController.updateRole
);

/**
 * @swagger
 * /roles/{id}:
 *   delete:
 *     summary: Delete a role
 *     tags: [Roles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Role ID
 *     responses:
 *       200:
 *         description: Role deactivated successfully
 *       400:
 *         description: Cannot delete role (assigned to users)
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 *       404:
 *         description: Role not found
 */
router.delete('/:id', 
  authController.hasPermission('archive_role'),
  roleController.deleteRole
);

/**
 * @swagger
 * /roles/{roleId}/assign/{userId}:
 *   post:
 *     summary: Assign role to user
 *     tags: [Roles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: roleId
 *         required: true
 *         schema:
 *           type: string
 *         description: Role ID
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       200:
 *         description: Role assigned successfully
 *       400:
 *         description: User already has this role
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 *       404:
 *         description: Role or user not found
 */
router.post('/:roleId/assign/:userId', 
  authController.hasPermission('update_user'),
  roleController.assignRoleToUser
);

/**
 * @swagger
 * /roles/{roleId}/remove/{userId}:
 *   delete:
 *     summary: Remove role from user
 *     tags: [Roles]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: roleId
 *         required: true
 *         schema:
 *           type: string
 *         description: Role ID
 *       - in: path
 *         name: userId
 *         required: true
 *         schema:
 *           type: string
 *         description: User ID
 *     responses:
 *       200:
 *         description: Role removed successfully
 *       400:
 *         description: User does not have this role
 *       401:
 *         description: Not authenticated
 *       403:
 *         description: Not authorized
 *       404:
 *         description: User not found
 */
router.delete('/:roleId/remove/:userId', 
  authController.hasPermission('update_user'),
  roleController.removeRoleFromUser
);

module.exports = router;