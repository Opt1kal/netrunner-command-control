

class SignalWave:
    def __init__(self):
        self.levels = "▁▂▃▄▅▆▇█"

        self.heights = [
            1, 3, 5, 7,
            5, 2, 4, 6,
            3, 1, 5, 7,
            4, 2, 6, 3,
            5, 7, 4, 1,
            3, 6, 2, 5,
        ]

        self.directions = [
            1,  1, -1, -1,
            -1,  1,  1, -1,
            1,  1, -1, -1,
            1,  1, -1,  1,
            -1, -1,  1,  1,
            1, -1,  1, -1,
        ]

        self.speeds = [
            1, 2, 1, 3,
            2, 1, 3, 1,
            2, 3, 1, 2,
            1, 3, 2, 1,
            2, 1, 3, 2,
            1, 2, 3, 1,
        ]

        self.tick = 0

    def next_frame(self) -> str:
        frame = "".join(
            self.levels[height]
            for height in self.heights
        )

        self.tick += 1

        for index, height in enumerate(self.heights):
            if self.tick % self.speeds[index] != 0:
                continue

            next_height = height + self.directions[index]

            if next_height >= len(self.levels):
                self.directions[index] = -1
                next_height = height - 1
            elif next_height < 0:
                self.directions[index] = 1
                next_height = height + 1

            self.heights[index] = next_height

        return frame