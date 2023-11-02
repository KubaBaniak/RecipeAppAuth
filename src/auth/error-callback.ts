import * as amqplib from 'amqplib';

export function ReplyErrorCallback(
  channel: amqplib.Channel,
  msg: amqplib.ConsumeMessage,
  error: any,
) {
  const { replyTo, correlationId } = msg.properties;
  if (replyTo) {
    error = Buffer.from(JSON.stringify(error.getError()));

    channel.publish('', replyTo, error, { correlationId });
    channel.ack(msg);
  }
}
