package mq

import (
	"context"
	"github.com/apache/rocketmq-client-go/v2/primitive"
	"github.com/apache/rocketmq-client-go/v2/producer"
	"github.com/minio/minio/internal/logger"
	"github.com/minio/minio/maitian/config"
	"github.com/minio/minio/maitian/mq/rocketmq"
)

var sender = make(chan primitive.Message, 100)
var receiver = make(chan primitive.MessageExt, 100)

type MqPubSub struct {
	rocketMqBus *rocketmq.RocketMqBus
}

var Pubsub *MqPubSub

func init() {
	Pubsub = &MqPubSub{
		rocketMqBus: &rocketmq.RocketMqBus{},
	}
}

func StartMQ() {
	logger.Info("[MQ] starting ")

	if err := Pubsub.StartPubsub(sender, receiver); err != nil {
		panic(err)
		return
	}

	//loop for mq task
	go func() {
		for {
			select {
			case msg := <-receiver:
				logger.Info("[MQ] receive message,topic: %s,  tag: %s", msg.Topic, msg.GetTags())
				//Pubsub.handleMQmessage(&msg)
			}
		}
	}()

}

func (ps *MqPubSub) StartPubsub(sender <-chan primitive.Message, receiver chan<- primitive.MessageExt) error {
	if err := ps.rocketMqBus.StartProducer(sender, GetProducerOptions()); err != nil {
		panic(err)
		return err
	}

	return nil
}

func Send(ctx context.Context, dist string, key string, msgData []byte) error {
	return Pubsub.send(ctx, dist, key, msgData)
}

// send Remote Message
func (ps *MqPubSub) send(ctx context.Context, distTopic, key string, msgData []byte) error {
	m := primitive.Message{
		Topic: distTopic,
		Body:  msgData,
	}
	m.WithKeys([]string{key})
	sender <- m
	return nil
}

func GetProducerOptions() []producer.Option {
	nameServer := config.GetString("mq.server")
	groupId := config.GetString("mq.group")
	if groupId == "" {
		groupId = "default"
	}

	var endPoint = []string{nameServer}
	return []producer.Option{producer.WithGroupName(groupId),
		producer.WithNameServer(endPoint),
		producer.WithTrace(&primitive.TraceConfig{
			GroupName:    groupId,
			Access:       primitive.Local,
			NamesrvAddrs: endPoint,
		})}
}
