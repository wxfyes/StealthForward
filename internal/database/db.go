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
	// 加上 busy_timeout 和 WAL 模式缓解 SQLite 并发写入锁死的问题
	DB, err = gorm.Open(sqlite.Open("stealthforward.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect database: %v", err)
	}

	// 限制底层的连接池，SQLite 只有支持单并发写，MaxOpenConns(1) 可以排队等待从而避免 BUSY 错误
	sqlDB, err := DB.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1)
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
