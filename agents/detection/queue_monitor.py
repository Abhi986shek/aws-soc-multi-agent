"""
Queue Monitor - background service that monitors CloudTrail events.
Runs every 30 seconds and triggers Agent 1 when queue reaches 5 events.
"""

import asyncio
from typing import List, Dict, Any

from logger import get_logger
from .tools.fetch_cloudtrail import fetch_cloudtrail_events

logger = get_logger("queue_monitor")


class EventQueue:
    """Priority queue for CloudTrail events (sorted by timestamp)."""

    def __init__(self):
        self.queue: List[Dict[str, Any]] = []
        self.max_size = 5

    def add_event(self, event: Dict[str, Any]):
        self.queue.append(event)
        self.queue.sort(key=lambda x: x.get("event_time", ""), reverse=True)

    def is_full(self) -> bool:
        return len(self.queue) >= self.max_size

    def get_batch(self) -> List[Dict[str, Any]]:
        batch = self.queue[: self.max_size]
        self.queue = self.queue[self.max_size :]
        return batch

    def size(self) -> int:
        return len(self.queue)


class QueueMonitor:
    """Background monitor: fetch every 30s and trigger the agent when full."""

    def __init__(self, agent_callback):
        self.queue = EventQueue()
        self.agent_callback = agent_callback
        self.running = False
        self.check_interval = 30

    async def start(self):
        self.running = True
        logger.info("Queue Monitor started (checking every 30s)")
        while self.running:
            try:
                events = fetch_cloudtrail_events(lookback_seconds=30)
                for event in events:
                    self.queue.add_event(event)
                logger.info(f"Queue: {self.queue.size()} events")
                if self.queue.is_full():
                    logger.info("Queue full - triggering Agent 1")
                    batch = self.queue.get_batch()
                    await self.agent_callback(batch)
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Queue monitor error: {e}")
                await asyncio.sleep(self.check_interval)

    def stop(self):
        self.running = False


async def run_queue_monitor(agent_callback):
    monitor = QueueMonitor(agent_callback)
    await monitor.start()
