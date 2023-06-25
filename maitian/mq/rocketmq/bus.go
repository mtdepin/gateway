package rocketmq

import (
	"context"
	"github.com/apache/rocketmq-client-go/v2"
	"github.com/apache/rocketmq-client-go/v2/primitive"
	"github.com/apache/rocketmq-client-go/v2/producer"
	"github.com/minio/minio/internal/logger"
	"sync"
	"time"
)

const MsgTypeProperty = "MsgTypeProperty"

type RocketMqBus struct {
	producer          rocketmq.Producer
	clusterConsumer   rocketmq.PushConsumer
	p2pConsumer       rocketmq.PushConsumer
	broadcastConsumer rocketmq.PushConsumer
	lock              sync.Mutex
}

func (bus *RocketMqBus) StartProducer(sender <-chan primitive.Message, proOptions []producer.Option) error {
	if bus.producer == nil {
		pro, err := rocketmq.NewProducer(proOptions...)
		if err != nil {
			return err
		}
		bus.producer = pro
	}

	err := bus.producer.Start()
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	//publish
	go func() {
		for {
			select {
			case msg := <-sender:
				res, err := bus.send(&msg, 5, time.Second*5)
				if err != nil {
					logger.Error("send on error message: %s", err.Error())
				} else {
					logger.Infof("send msg id: %s, content: %s", res.MsgID, string(msg.Body))
				}
			}
		}
	}()
	return nil
}

func (bus *RocketMqBus) send(msg *primitive.Message, attempts int, sleep time.Duration) (*primitive.SendResult, error) {
	res, err := bus.producer.SendSync(context.Background(), msg)
	if err != nil {
		if attempts--; attempts > 0 {
			logger.Infof("retry send error: %s. attemps #%d after %s.", err.Error(), attempts, sleep)
			time.Sleep(sleep)
			return bus.send(msg, attempts, sleep*2)
		}
		return res, err
	}
	return res, err
}
