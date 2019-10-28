package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lucabrasi83/vscan/logging"
	"github.com/lucabrasi83/vscan/postgresdb"
)

// GetAllUsers is a Gin Handler to return the list of all users provisioned
func GetAllUsers(c *gin.Context) {
	users, err := postgresdb.DBInstance.FetchAllUsers()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unable to fetch users from database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

// GetUser is a Gin handler to return a specific user
func GetUser(c *gin.Context) {
	userInput := c.Param("user-id")

	userFound, err := postgresdb.DBInstance.FetchUser(userInput)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "cannot find requested user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": *userFound})
}

// CreateUser is a Gin handler to create a user
func CreateUser(c *gin.Context) {

	var newUser VulscanoUserCreate

	if err := c.ShouldBindJSON(&newUser); err != nil {
		logging.VSCANLog("error", "User creation request failed %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !validateEmail(newUser.Email) || len(newUser.Email) > 60 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Email Address given. Note: " +
			"maximum of 60 characters allowed for this field."})
		return
	}
	if !validatePassword(newUser.Password) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password given does not meet minimum length/complexity requirements",
		})
		return
	}
	if strings.ToLower(newUser.Role) != rootRole && strings.ToLower(newUser.Role) != userRole {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Only vulscanoroot and vulscanouser are possible values for the user role",
		})
		return
	}

	err := postgresdb.DBInstance.InsertNewUser(
		strings.ToLower(newUser.Email),
		newUser.Password,
		strings.ToUpper(newUser.Enterprise),
		strings.ToLower(newUser.Role))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": strings.ToLower(newUser.Email) + " user successfully created"})

}

// UpdateUser is a Gin handler to update a user
func UpdateUser(c *gin.Context) {

	var updateUser VulscanoUserPatch
	user := c.Param("user-id")

	if err := c.ShouldBindJSON(&updateUser); err != nil {
		logging.VSCANLog("error", "user update request failed %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if updateUser.Enterprise == "" && updateUser.Role == "" && updateUser.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no value provided"})
		return
	}

	if isDBUser := postgresdb.DBInstance.AssertUserExists(user); !isDBUser {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user " + user + " does not exist"})
		return
	}

	if updateUser.Password != "" && !validatePassword(updateUser.Password) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password given does not meet minimum length/complexity requirements",
		})
		return
	}

	if strings.ToLower(user) == rootUser && strings.ToLower(updateUser.Role) != "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "update of root user role is not allowed",
		})
		return
	}
	if updateUser.Role != "" && strings.ToLower(updateUser.Role) != rootRole && strings.ToLower(updateUser.
		Role) != userRole {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Only vulscanoroot and vulscanouser are possible values for the user role",
		})
		return
	}
	err := postgresdb.DBInstance.PatchUser(user, updateUser.Role, updateUser.Password, updateUser.Enterprise)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "user updated failed",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": "user " + user + " successfully updated"})
}

// DeleteUser is a Gin handler to delete a user
func DeleteUser(c *gin.Context) {

	userObj := struct {
		Users []string `json:"users" binding:"required"`
	}{}

	if errBind := c.ShouldBindJSON(&userObj); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "users not specified in body"})
		return
	}
	users := userObj.Users

	for _, u := range users {
		if u == rootUser {
			c.JSON(http.StatusBadRequest, gin.H{"error": "cannot delete root user"})
			return
		}

		if isDBUser := postgresdb.DBInstance.AssertUserExists(u); !isDBUser {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user " + u + " does not exist"})
			return
		}
	}

	err := postgresdb.DBInstance.DeleteUser(users)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": "users successfully deleted"})

}
