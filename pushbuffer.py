#A PushBuffer is an iterable that contains a fixed number of items
#When a new item is pushed into a PushBuffer, it will be placed in the front (lowest index)
# and all other items are shifted one place higher
#If pushing a new item would require more space than the size allows, 
# the oldest item (highest index) is discarded.

#PushBuffers can use get() and set() to read and write items by index (although each item's index changes upon a push)
#Could I have emulated a container type using __getitem__ and __setitem__ instead? Yes. Would that be better? Probably also yes.

class PushBuffer:
	
	def push(self, newItem):
		self.__memory.pop()
		self.__memory.insert(0, newItem)
	
	def __init__(self, size = 100, items = None):
		
		if size <= 0:
			raise ValueError('Size must be greater than zero')
		
		self.size = size
		#Create empty list with specified size
		self.__memory = [None] * self.size
		
		#Import items by pushing each one in reverse order (so that order is preserved)
		if items != None:
			for item in items[::-1]:
				self.push(item)
		
	def get(self, index):
		return self.__memory[index]
	
	def set(self, index, newValue):
		self.__memory[index] = newValue

	#Clears all values 
	def flush(self):
		self.__memory = [None] * self.size

		
	#Returns the currently stored values as a tuple
	def getValues(self):
		return tuple(self.__memory)

	#Returns only entries that aren't none as a tuple
	def getNonNoneValues(self):
		nonNoneValues = []
		for value in self.__memory:
			if value != None: nonNoneValues.append(value)

		return tuple(nonNoneValues)
		
	
	def __str__(self):
		return str(self.__memory)
		
	def __repr__(self):
		return "PushBuffer(%d, %s)" % (self.size, str(self.__memory))
		
	def __iter__(self):
		return iter(self.__memory)
		
	