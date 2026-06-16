package database

import (
	"log"

	"github.com/glebarez/sqlite"
	"github.com/wangn9900/StealthForward/internal/models"
	"gorm.io/gorm"
)

var DB *gorm.DB

// InitDB 初始化数据库连接
func InitDB() {
	var err error
	// 暂时使用 SQLite 方便开发调试
	DB, err = gorm.Open(sqlite.Open("stealthforward.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// 自动迁移表结构
	log.Println("Migrating database tables...")
	err = DB.AutoMigrate(
		&models.EntryNode{},
		&models.ExitNode{},
		&models.ForwardingRule{},
		&models.NodeMapping{},
		&models.SystemSetting{},
		&models.CloudAccount{},
		&models.SSHKey{},
		&models.PortForward{},
	)
	if err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}
	log.Println("Database migration completed.")
}
