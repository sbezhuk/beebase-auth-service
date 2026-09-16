package auth

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/sbezhuk/beebase-auth-service/internal/domain/user"
	"log/slog"
	"time"
)

type DeletionWorker struct {
	store DeletionJobStore
	users interface {
		Delete(context.Context, uuid.UUID) error
	}
	clients map[string]AccountCleanupClient
	log     *slog.Logger
}

func NewDeletionWorker(store DeletionJobStore, users interface {
	Delete(context.Context, uuid.UUID) error
}, clients map[string]AccountCleanupClient, log *slog.Logger) *DeletionWorker {
	return &DeletionWorker{store: store, users: users, clients: clients, log: log}
}

func (w *DeletionWorker) RunOnce(ctx context.Context) error {
	job, err := w.store.ClaimDeletion(ctx)
	if err != nil || job == nil {
		return err
	}
	for _, step := range job.Steps {
		if step.Status == "completed" {
			continue
		}
		client, ok := w.clients[step.Service]
		if !ok {
			return w.retry(ctx, job, step, fmt.Errorf("missing cleanup client"))
		}
		if err := client.DeleteUserData(ctx, job.UserID); err != nil {
			return w.retry(ctx, job, step, err)
		}
		if err := w.store.CompleteDeletionStep(ctx, job.ID, step.Service); err != nil {
			return err
		}
	}
	if err := w.users.Delete(ctx, job.UserID); err != nil && !errors.Is(err, user.ErrNotFound) {
		return err
	}
	return w.store.CompleteDeletionJob(ctx, job.ID)
}

func (w *DeletionWorker) retry(ctx context.Context, job *DeletionJob, step DeletionStep, cause error) error {
	if err := w.store.RetryDeletionStep(ctx, job.ID, step.Service, step.AttemptCount+1, cause.Error()); err != nil {
		return err
	}
	w.log.Error("account deletion step failed", "service", step.Service, "attempt", step.AttemptCount+1, "error_type", fmt.Sprintf("%T", cause))
	return nil
}

func (w *DeletionWorker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.RunOnce(ctx); err != nil {
				w.log.Error("account deletion worker failed", "error_type", fmt.Sprintf("%T", err))
			}
		}
	}
}
